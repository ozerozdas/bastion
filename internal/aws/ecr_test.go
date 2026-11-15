package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

const testImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// fakeDescribeImages answers DescribeImages from memory, so tag resolution is
// tested without reaching ECR.
type fakeDescribeImages struct {
	out  *ecr.DescribeImagesOutput
	err  error
	last *ecr.DescribeImagesInput
}

func (f *fakeDescribeImages) DescribeImages(_ context.Context, in *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	f.last = in
	return f.out, f.err
}

// TestResolveImageByTag: a tag is looked up and its digest is returned.
func TestResolveImageByTag(t *testing.T) {
	digest := testImageDigest
	api := &fakeDescribeImages{out: &ecr.DescribeImagesOutput{ImageDetails: []ecrtypes.ImageDetail{{
		ImageDigest: &digest,
		ImageTags:   []string{"latest"},
	}}}}

	image, err := resolveImage(t.Context(), api, "t2n-worker", "latest", "")
	if err != nil {
		t.Fatalf("resolveImage: %v", err)
	}
	if image.Tag != "latest" || image.Digest != digest {
		t.Fatalf("image = %+v, want latest pinned to %s", image, digest)
	}
	if got := deref(api.last.ImageIds[0].ImageTag); got != "latest" {
		t.Errorf("DescribeImages image tag = %q, want latest", got)
	}
	if api.last.ImageIds[0].ImageDigest != nil {
		t.Error("DescribeImages was given a digest as well as a tag")
	}
	if got := deref(api.last.RepositoryName); got != "t2n-worker" {
		t.Errorf("DescribeImages repository = %q, want t2n-worker", got)
	}
}

// TestResolveImageByDigestPicksATag: a digest-pinned reference still yields a
// tag for the asset, preferring "latest".
func TestResolveImageByDigestPicksATag(t *testing.T) {
	digest := testImageDigest
	api := &fakeDescribeImages{out: &ecr.DescribeImagesOutput{ImageDetails: []ecrtypes.ImageDetail{{
		ImageDigest: &digest,
		ImageTags:   []string{"v1.2.3", "stable", "latest"},
	}}}}

	image, err := resolveImage(t.Context(), api, "t2n-worker", "", digest)
	if err != nil {
		t.Fatalf("resolveImage: %v", err)
	}
	if image.Tag != "latest" || image.Digest != digest {
		t.Fatalf("image = %+v, want latest pinned to %s", image, digest)
	}
	if got := deref(api.last.ImageIds[0].ImageDigest); got != digest {
		t.Errorf("DescribeImages image digest = %q, want %q", got, digest)
	}
	if api.last.ImageIds[0].ImageTag != nil {
		t.Error("DescribeImages was given a tag as well as a digest")
	}
}

// TestResolveImageRejectsIncompleteAnswers: ECR must name both a tag and a
// digest, or the asset would be unpinned.
func TestResolveImageRejectsIncompleteAnswers(t *testing.T) {
	digest := testImageDigest
	tests := []struct {
		name   string
		tag    string
		digest string
		out    *ecr.DescribeImagesOutput
	}{
		{name: "no image", tag: "latest", out: &ecr.DescribeImagesOutput{}},
		{name: "no digest", tag: "latest", out: &ecr.DescribeImagesOutput{ImageDetails: []ecrtypes.ImageDetail{{ImageTags: []string{"latest"}}}}},
		{name: "no tag for digest", digest: digest, out: &ecr.DescribeImagesOutput{ImageDetails: []ecrtypes.ImageDetail{{ImageDigest: &digest}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeDescribeImages{out: test.out}
			if _, err := resolveImage(t.Context(), api, "t2n-worker", test.tag, test.digest); err == nil {
				t.Fatal("resolveImage accepted an incomplete answer")
			}
		})
	}
}

// TestResolveImageReturnsTheAPIError: a missing tag stays distinguishable from
// a decoding failure.
func TestResolveImageReturnsTheAPIError(t *testing.T) {
	want := errors.New("ImageNotFoundException")
	api := &fakeDescribeImages{err: want}
	if _, err := resolveImage(t.Context(), api, "t2n-worker", "missing", ""); !errors.Is(err, want) {
		t.Fatalf("resolveImage error = %v, want %v", err, want)
	}
}

// TestDisplayTag: the asset's tag is deterministic for a digest.
func TestDisplayTag(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		want string
	}{
		{name: "prefers latest", tags: []string{"stable", "latest", "v1"}, want: "latest"},
		{name: "first alphabetically", tags: []string{"v2", "", "v1"}, want: "v1"},
		{name: "none", tags: nil, want: ""},
	}
	for _, test := range tests {
		if got := displayTag(test.tags); got != test.want {
			t.Errorf("%s: displayTag(%v) = %q, want %q", test.name, test.tags, got, test.want)
		}
	}
}
