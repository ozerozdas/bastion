package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// Discovery limits. Discovery is a preview for the UI, not an inventory: an
// account can hold hundreds of repositories and thousands of tags each, and
// every repository costs one DescribeImages call. One page per repository and
// a hard repository cap keep the picker responsive and the API bill small.
const (
	// RecentTagLimit is how many of a repository's newest tags discovery offers.
	RecentTagLimit = 10
	// RepositoryLimit caps how many repositories one discovery lists.
	RepositoryLimit = 100
	// imagePageSize is the single DescribeImages page read per repository.
	imagePageSize = 100
)

// Repository is one ECR repository with its most recently pushed tags.
type Repository struct {
	// Name is the repository name inside the registry ("t2n-api").
	Name string
	// URI is the registry-qualified repository
	// ("143709573002.dkr.ecr.eu-central-1.amazonaws.com/t2n-api").
	URI string
	// Tags are the newest tags, newest first.
	Tags []Tag
}

// Tag is one image tag in a repository.
type Tag struct {
	Name     string
	Digest   string
	PushedAt time.Time
}

// Image is one ECR image resolved from a tag or a digest.
type Image struct {
	// Tag is the tag the image is known by: the requested one, or a tag that
	// points at the requested digest.
	Tag string
	// Digest is the image's sha256 digest.
	Digest string
}

// Credentials is a short-lived ECR registry login. It is derived from
// ecr:GetAuthorizationToken and is never stored or logged.
type Credentials struct {
	Username  string
	Password  string
	ExpiresAt time.Time
}

// Repositories lists the account's ECR repositories with their newest tags.
// It is discovery only: no image is pulled.
func (c *Client) Repositories(ctx context.Context) ([]Repository, error) {
	const op = "list ECR repositories"

	cfg, err := awscfg.LoadDefaultConfig(ctx, c.loadOptions()...)
	if err != nil {
		return nil, &Error{Op: op, Hint: configHint(err, c.profile), Err: err}
	}
	client := ecr.NewFromConfig(cfg)

	repositories := make([]Repository, 0)
	pages := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})
	for pages.HasMorePages() && len(repositories) < RepositoryLimit {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, &Error{Op: op, Code: errorCode(err), Hint: ecrHint(err, c.profile), Err: err}
		}
		for _, repo := range page.Repositories {
			if len(repositories) >= RepositoryLimit {
				break
			}
			repository := Repository{
				Name: deref(repo.RepositoryName),
				URI:  deref(repo.RepositoryUri),
			}
			if repository.Name == "" {
				continue
			}
			tags, err := c.recentTags(ctx, client, repository.Name)
			if err != nil {
				return nil, err
			}
			repository.Tags = tags
			repositories = append(repositories, repository)
		}
	}
	sort.Slice(repositories, func(i, j int) bool {
		return repositories[i].Name < repositories[j].Name
	})
	return repositories, nil
}

// recentTags reads a repository's newest tagged images and flattens them into
// one entry per tag. Only tags are offered: a digest alone cannot be displayed
// or re-pushed as a tag. One DescribeImages page is enough for RecentTagLimit:
// ECR returns newest first and 100 images is far more than the 10 tags shown.
func (c *Client) recentTags(ctx context.Context, client *ecr.Client, repository string) ([]Tag, error) {
	const op = "list ECR images"

	maxResults := int32(imagePageSize)
	page, err := client.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RepositoryName: &repository,
		Filter:         &ecrtypes.DescribeImagesFilter{TagStatus: ecrtypes.TagStatusTagged},
		MaxResults:     &maxResults,
	})
	if err != nil {
		return nil, &Error{Op: op, Code: errorCode(err), Hint: ecrHint(err, c.profile), Err: err}
	}

	tags := make([]Tag, 0, RecentTagLimit)
	for _, image := range page.ImageDetails {
		digest := deref(image.ImageDigest)
		if digest == "" {
			continue
		}
		pushedAt := time.Time{}
		if image.ImagePushedAt != nil {
			pushedAt = image.ImagePushedAt.UTC()
		}
		for _, name := range image.ImageTags {
			if name == "" {
				continue
			}
			tags = append(tags, Tag{Name: name, Digest: digest, PushedAt: pushedAt})
		}
	}

	sort.Slice(tags, func(i, j int) bool {
		if tags[i].PushedAt.Equal(tags[j].PushedAt) {
			return tags[i].Name > tags[j].Name
		}
		return tags[i].PushedAt.After(tags[j].PushedAt)
	})
	if len(tags) > RecentTagLimit {
		tags = tags[:RecentTagLimit]
	}
	return tags, nil
}

// Image resolves one image in repository by tag or by digest, so a scan can
// pin a tag to the digest it will read. Exactly one of tag and digest is
// needed; when only the digest is known, a tag pointing at it is returned so an
// asset can record one.
func (c *Client) Image(ctx context.Context, repository, tag, digest string) (Image, error) {
	const op = "describe ECR image"

	if repository == "" || (tag == "" && digest == "") {
		return Image{}, &Error{Op: op, Hint: "an ECR repository and a tag or a digest are required"}
	}
	cfg, err := awscfg.LoadDefaultConfig(ctx, c.loadOptions()...)
	if err != nil {
		return Image{}, &Error{Op: op, Hint: configHint(err, c.profile), Err: err}
	}
	image, err := resolveImage(ctx, ecr.NewFromConfig(cfg), repository, tag, digest)
	if err != nil {
		return Image{}, &Error{Op: op, Code: errorCode(err), Hint: ecrHint(err, c.profile), Err: err}
	}
	return image, nil
}

// describeImageAPI is the one ECR call tag resolution needs, so tests fake it
// instead of reaching AWS.
type describeImageAPI interface {
	DescribeImages(context.Context, *ecr.DescribeImagesInput, ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
}

// resolveImage asks ECR for one image and returns its tag and digest. A tag
// identifies the image when one is given; otherwise the digest does.
func resolveImage(ctx context.Context, api describeImageAPI, repository, tag, digest string) (Image, error) {
	identifier := ecrtypes.ImageIdentifier{}
	if tag != "" {
		identifier.ImageTag = &tag
	} else {
		identifier.ImageDigest = &digest
	}
	out, err := api.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RepositoryName: &repository,
		ImageIds:       []ecrtypes.ImageIdentifier{identifier},
	})
	if err != nil {
		return Image{}, err
	}
	if len(out.ImageDetails) == 0 {
		return Image{}, errors.New("ECR returned no image")
	}

	detail := out.ImageDetails[0]
	image := Image{Digest: deref(detail.ImageDigest), Tag: tag}
	if image.Tag == "" {
		image.Tag = displayTag(detail.ImageTags)
	}
	switch {
	case image.Digest == "":
		return Image{}, errors.New("ECR returned an image without a digest")
	case image.Tag == "":
		return Image{}, errors.New("ECR returned an image without a tag")
	}
	return image, nil
}

// displayTag picks the tag an asset records for a digest: "latest" when the
// image carries it, otherwise the lexicographically first tag.
func displayTag(tags []string) string {
	chosen := ""
	for _, tag := range tags {
		if tag == "" {
			continue
		}
		if tag == "latest" {
			return tag
		}
		if chosen == "" || tag < chosen {
			chosen = tag
		}
	}
	return chosen
}

// AuthorizationToken returns a short-lived registry login for this account's
// ECR registry. The token is valid for 12 hours; bastion keeps it in memory
// for one scan and never writes it anywhere.
func (c *Client) AuthorizationToken(ctx context.Context) (Credentials, error) {
	const op = "get ECR authorization token"

	cfg, err := awscfg.LoadDefaultConfig(ctx, c.loadOptions()...)
	if err != nil {
		return Credentials{}, &Error{Op: op, Hint: configHint(err, c.profile), Err: err}
	}
	out, err := ecr.NewFromConfig(cfg).GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return Credentials{}, &Error{Op: op, Code: errorCode(err), Hint: ecrHint(err, c.profile), Err: err}
	}
	if len(out.AuthorizationData) == 0 {
		return Credentials{}, &Error{Op: op, Hint: "ECR returned no authorization token", Err: nil}
	}

	data := out.AuthorizationData[0]
	encoded := deref(data.AuthorizationToken)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Never include the token itself in the error: it is a credential.
		return Credentials{}, &Error{Op: op, Hint: "ECR returned an unreadable authorization token", Err: err}
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || username == "" || password == "" {
		return Credentials{}, &Error{Op: op, Hint: "ECR returned an unreadable authorization token"}
	}
	credentials := Credentials{Username: username, Password: password}
	if data.ExpiresAt != nil {
		credentials.ExpiresAt = data.ExpiresAt.UTC()
	}
	return credentials, nil
}

// ecrHint explains a failed ECR call. The API error code is kept because it
// tells the user which permission or repository to fix.
func ecrHint(err error, profile string) string {
	if code := errorCode(err); code != "" {
		switch code {
		case "AccessDenied", "AccessDeniedException":
			return "AWS denied the ECR request (" + code + "); check the profile's ECR permissions"
		case "RepositoryNotFoundException":
			return "the ECR repository was not found in this region"
		case "ImageNotFoundException":
			return "the image tag or digest was not found in this ECR repository"
		case "InvalidClientTokenId", "UnrecognizedClientException",
			"ExpiredToken", "ExpiredTokenException", "RequestExpired",
			"SignatureDoesNotMatch":
			return "AWS rejected the credentials (" + code + "); refresh the AWS session and test again"
		default:
			return "AWS returned " + code
		}
	}
	if credentialsFailure(err.Error()) {
		return credentialsHint(profile)
	}
	return "could not reach Amazon ECR; check the network and the profile"
}
