//go:build awsreal

package aws

import (
	"strings"
	"testing"
)

// TestRealGetCallerIdentity is the manual check behind the AWS connection: it
// uses this machine's own default credential chain. Only the account id and the
// ARN shape are printed; no credential is read or logged.
//
//	go test -tags awsreal ./internal/aws -run TestRealGetCallerIdentity -v
func TestRealGetCallerIdentity(t *testing.T) {
	client, err := New(Config{Profile: "default", Region: "eu-central-1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	identity, err := client.Identity(t.Context())
	if err != nil {
		t.Fatalf("GetCallerIdentity: %v", err)
	}
	if identity.Account == "" || !strings.HasPrefix(identity.ARN, "arn:") {
		t.Fatalf("identity = %+v, want an account and an ARN", identity)
	}
	t.Logf("account=%s arn=%s", identity.Account, arnShape(identity.ARN))
}

// arnShape masks the resource name, which can carry a user or role name.
func arnShape(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return "<unexpected ARN>"
	}
	return strings.Join(parts[:5], ":") + ":<resource>"
}
