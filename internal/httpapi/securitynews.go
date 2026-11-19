package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/securitynews"
)

// securityNewsUnavailable is the detail for the Security News endpoints when
// serve did not wire a service (some tests build a Server without one).
const securityNewsUnavailable = "Security News is not configured; start bastion with its data directory"

// GetSecurityNews implements gen.StrictServerInterface. With the feature off
// the service returns the settings without a network call; when it is on, a
// stale source is refreshed before the response.
func (s *Server) GetSecurityNews(ctx context.Context, _ gen.GetSecurityNewsRequestObject) (gen.GetSecurityNewsResponseObject, error) {
	if s.securityNews == nil {
		return gen.GetSecurityNews500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", securityNewsUnavailable),
		}, nil
	}
	return gen.GetSecurityNews200JSONResponse(securityNewsFeedResponse(s.securityNews.Feed(ctx))), nil
}

// SetSecurityNews implements gen.StrictServerInterface. Only the UI calls it;
// the MCP server only reads.
func (s *Server) SetSecurityNews(_ context.Context, request gen.SetSecurityNewsRequestObject) (gen.SetSecurityNewsResponseObject, error) {
	if s.securityNews == nil {
		return gen.SetSecurityNews500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", securityNewsUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetSecurityNews400ApplicationProblemPlusJSONResponse{
			ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{
				Body: newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
			},
		}, nil
	}

	var sources []string
	if request.Body.Sources != nil {
		sources = *request.Body.Sources
	}
	if err := s.securityNews.Set(request.Body.Enabled, sources); err != nil {
		// An unknown source id is a client error; a storage failure is the
		// server's. Both leave the previous setting in place.
		if errors.Is(err, securitynews.ErrUnknownSource) {
			return gen.SetSecurityNews400ApplicationProblemPlusJSONResponse{
				ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse{
					Body: newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
				},
			}, nil
		}
		s.log.Error("store Security News setting", "error", err)
		return gen.SetSecurityNews500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the Security News choice; see the server log"),
		}, nil
	}

	return gen.SetSecurityNews200JSONResponse(securityNewsSettingsResponse(s.securityNews)), nil
}

// securityNewsSettingsResponse maps the current setting onto the API shape.
func securityNewsSettingsResponse(service *securitynews.Service) gen.SecurityNewsSettings {
	settings := service.Settings()
	return gen.SecurityNewsSettings{
		Enabled: settings.Enabled,
		Sources: securityNewsSourceResponses(settings.Sources),
	}
}

// securityNewsFeedResponse maps the domain feed onto the API shape.
func securityNewsFeedResponse(feed securitynews.Feed) gen.SecurityNewsFeed {
	items := make([]gen.SecurityNewsItem, 0, len(feed.Items))
	for _, item := range feed.Items {
		items = append(items, gen.SecurityNewsItem{
			Title:     item.Title,
			Source:    item.Source,
			SourceId:  item.SourceID,
			Published: item.Published,
			Link:      item.Link,
			Summary:   item.Summary,
		})
	}
	return gen.SecurityNewsFeed{
		Enabled: feed.Enabled,
		Sources: securityNewsSourceResponses(feed.Sources),
		Items:   items,
	}
}

func securityNewsSourceResponses(sources []securitynews.SourceState) []gen.SecurityNewsSource {
	out := make([]gen.SecurityNewsSource, 0, len(sources))
	for _, source := range sources {
		entry := gen.SecurityNewsSource{
			Id:          source.ID,
			Name:        source.Name,
			Recommended: source.Recommended,
			Enabled:     source.Enabled,
		}
		if source.Error != "" {
			message := source.Error
			entry.Error = &message
		}
		out = append(out, entry)
	}
	return out
}
