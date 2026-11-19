package main

import (
	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/securitynews"
)

// newSecurityNewsService wires the opt-in Security News feed (#192). It
// performs no I/O: only the stored setting is read, and while it is off the
// service never fetches a feed.
func newSecurityNewsService(paths app.Paths) *securitynews.Service {
	return securitynews.New(securitynews.Config{
		DataDir: paths.DataDir,
		Version: version,
	})
}
