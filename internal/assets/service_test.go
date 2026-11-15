package assets

import (
	"errors"
	"testing"
)

func TestValidateImageRef(t *testing.T) {
	valid := []string{
		"nginx:latest",
		"ghcr.io/ozerozdas/bastion:v1.2.3",
		"registry.example.com:5000/team/app@sha256:abcdef",
		"my_image-1.0",
	}
	for _, ref := range valid {
		if err := validateImageRef(ref); err != nil {
			t.Errorf("validateImageRef(%q) = %v, want nil", ref, err)
		}
	}

	invalid := []string{
		"",
		"-nginx:latest",
		"nginx latest",
		"nginx;rm -rf /",
		"nginx#latest",
		"nginx\nlatest",
	}
	for _, ref := range invalid {
		err := validateImageRef(ref)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("validateImageRef(%q) = %v, want ErrInvalid", ref, err)
		}
	}
}
