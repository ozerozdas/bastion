// Package aws answers "who am I" for an AWS connection and, later, reads ECR.
//
// Bastion never stores AWS credentials: every call resolves them through the
// SDK's default chain (environment, shared config profile, SSO cache, instance
// role), so the session the user already established with the aws CLI is the
// one that is used. A connection stores only a profile name and a region.
package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Config configures a Client. Profile and Region come from the connection row.
type Config struct {
	// Profile is the shared-config profile name. Empty means the SDK's own
	// default resolution (AWS_PROFILE, then "default").
	Profile string
	// Region is the region the connection was created with.
	Region string
	// Version is reported in the SDK's user agent as "bastion/<Version>".
	Version string
}

// Identity is what STS GetCallerIdentity reports. It is not a credential: the
// account id and ARN are safe to show and to keep in the connection's config.
type Identity struct {
	Account string
	ARN     string
	UserID  string
}

// Error is a failed AWS call with a user-facing Hint. Raw SDK error text can
// carry request ids and URLs, so the caller logs it and Hint is what the user
// sees.
type Error struct {
	Op string
	// Code is the AWS error code when the SDK reported one (ExpiredToken,
	// AccessDenied, ...). It is safe to log.
	Code string
	Hint string
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "aws: " + e.Op + ": " + e.Hint
	}
	return "aws: " + e.Op + ": " + e.Hint + ": " + e.Err.Error()
}

// Unwrap exposes the SDK error so context cancellation and deadlines can be
// matched by the caller.
func (e *Error) Unwrap() error { return e.Err }

// Client calls AWS with credentials from the default chain. It is safe for
// concurrent use.
type Client struct {
	profile string
	region  string
	version string
}

// New validates cfg and returns a client. It makes no network call: the
// credential chain is resolved by the first request.
func New(cfg Config) (*Client, error) {
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		return nil, errors.New("aws: region is required")
	}
	version := strings.TrimSpace(cfg.Version)
	if version == "" {
		version = "dev"
	}
	return &Client{
		profile: strings.TrimSpace(cfg.Profile),
		region:  region,
		version: version,
	}, nil
}

// Identity calls sts:GetCallerIdentity, which needs no permission beyond being
// authenticated. It doubles as the connection test.
func (c *Client) Identity(ctx context.Context) (Identity, error) {
	const op = "get caller identity"

	cfg, err := awscfg.LoadDefaultConfig(ctx, c.loadOptions()...)
	if err != nil {
		return Identity{}, &Error{Op: op, Hint: configHint(err, c.profile), Err: err}
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, &Error{
			Op:   op,
			Code: errorCode(err),
			Hint: callHint(err, c.profile),
			Err:  err,
		}
	}
	return Identity{
		Account: deref(out.Account),
		ARN:     deref(out.Arn),
		UserID:  deref(out.UserId),
	}, nil
}

// loadOptions pins the connection's region and profile. The profile is only
// forced when the connection names one, so an empty profile keeps the SDK's
// normal precedence.
func (c *Client) loadOptions() []func(*awscfg.LoadOptions) error {
	opts := []func(*awscfg.LoadOptions) error{
		awscfg.WithRegion(c.region),
		awscfg.WithAppID("bastion/" + c.version),
	}
	if c.profile != "" {
		opts = append(opts, awscfg.WithSharedConfigProfile(c.profile))
	}
	return opts
}

// configHint explains a failure to build the SDK configuration, which is
// almost always a missing profile or missing credentials.
func configHint(err error, profile string) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "failed to get shared config profile"):
		if profile != "" {
			return fmt.Sprintf("AWS profile %q was not found in ~/.aws/config", profile)
		}
		return "the AWS profile was not found in ~/.aws/config"
	case credentialsFailure(msg):
		return credentialsHint(profile)
	}
	return "could not load the AWS configuration; check ~/.aws/config and the profile name"
}

// callHint explains a failed STS call. The API error code is kept because it
// tells the user which half of the setup to fix.
func callHint(err error, profile string) string {
	if code := errorCode(err); code != "" {
		switch code {
		case "InvalidClientTokenId", "UnrecognizedClientException",
			"ExpiredToken", "ExpiredTokenException", "RequestExpired",
			"SignatureDoesNotMatch":
			return "AWS rejected the credentials (" + code + "); refresh the AWS session and test again"
		case "AccessDenied", "AccessDeniedException":
			return "AWS denied sts:GetCallerIdentity (" + code + "); check the profile's permissions"
		default:
			return "AWS returned " + code
		}
	}
	if credentialsFailure(err.Error()) {
		return credentialsHint(profile)
	}
	return "could not reach AWS; check the network and the profile"
}

// errorCode returns the AWS error code when the SDK reported one.
func errorCode(err error) string {
	var apiErr interface{ ErrorCode() string }
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// credentialsHint tells the user how to establish a session for the profile.
func credentialsHint(profile string) string {
	if profile != "" {
		return fmt.Sprintf("no usable credentials for profile %q; run `aws sso login --profile %s` or configure keys for it", profile, profile)
	}
	return "no AWS credentials found; run `aws configure` or `aws sso login`"
}

// credentialsFailure recognises the SDK's credential-chain errors. They carry
// no API error code, so the message is the only signal.
func credentialsFailure(msg string) bool {
	for _, needle := range []string{
		"failed to refresh cached credentials",
		"failed to load credentials",
		"failed to retrieve credentials",
		"no EC2 IMDS role found",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// deref reads an optional SDK string.
func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
