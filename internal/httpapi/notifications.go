package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/notifications"
)

// notificationsUnavailable is the detail for the notification endpoints when
// serve did not wire a service (some tests build a Server without one).
const notificationsUnavailable = "notifications are not configured; start bastion with its database and data directory"

// GetNotificationSettings implements gen.StrictServerInterface. The Slack
// webhook and the SMTP password are never part of the response.
func (s *Server) GetNotificationSettings(_ context.Context, _ gen.GetNotificationSettingsRequestObject) (gen.GetNotificationSettingsResponseObject, error) {
	if s.notifications == nil {
		return gen.GetNotificationSettings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", notificationsUnavailable),
		}, nil
	}
	return gen.GetNotificationSettings200JSONResponse(notificationSettingsResponse(s.notifications)), nil
}

// SetNotificationSettings implements gen.StrictServerInterface. The body
// merges into the stored settings: fields it omits are left untouched.
func (s *Server) SetNotificationSettings(_ context.Context, request gen.SetNotificationSettingsRequestObject) (gen.SetNotificationSettingsResponseObject, error) {
	if s.notifications == nil {
		return gen.SetNotificationSettings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", notificationsUnavailable),
		}, nil
	}
	if request.Body == nil {
		return gen.SetNotificationSettings400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "the request body is required"),
		), nil
	}

	body := request.Body
	in := notifications.UpdateInput{
		Enabled:       body.Enabled,
		SlackEnabled:  body.SlackEnabled,
		SlackWebhook:  body.SlackWebhook,
		EmailEnabled:  body.EmailEnabled,
		SMTPHost:      body.SmtpHost,
		SMTPUsername:  body.SmtpUsername,
		From:          body.From,
		To:            body.To,
		EmailPassword: body.EmailPassword,
	}
	if body.SmtpPort != nil {
		port := int(*body.SmtpPort)
		in.SMTPPort = &port
	}
	if body.ClearSlackWebhook != nil {
		in.ClearSlackWebhook = *body.ClearSlackWebhook
	}
	if body.ClearEmailPassword != nil {
		in.ClearEmailPassword = *body.ClearEmailPassword
	}
	if body.Threshold != nil {
		threshold := string(*body.Threshold)
		in.Threshold = &threshold
	}

	if _, err := s.notifications.Update(in); err != nil {
		if errors.Is(err, notifications.ErrInvalid) {
			return gen.SetNotificationSettings400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		}
		s.log.Error("store notification settings", "error", err)
		return gen.SetNotificationSettings500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not store the notification settings; see the server log"),
		}, nil
	}
	return gen.SetNotificationSettings200JSONResponse(notificationSettingsResponse(s.notifications)), nil
}

// SendTestNotification implements gen.StrictServerInterface. It posts a sample
// message through every configured channel, whether or not that channel is
// enabled.
func (s *Server) SendTestNotification(ctx context.Context, _ gen.SendTestNotificationRequestObject) (gen.SendTestNotificationResponseObject, error) {
	if s.notifications == nil {
		return gen.SendTestNotification500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", notificationsUnavailable),
		}, nil
	}

	err := s.notifications.SendTest(ctx)
	switch {
	case err == nil:
		return gen.SendTestNotification204Response{}, nil
	case errors.Is(err, notifications.ErrNoWebhook),
		errors.Is(err, notifications.ErrNotConfigured),
		errors.Is(err, notifications.ErrNoEmailPassword),
		errors.Is(err, notifications.ErrInvalid):
		return gen.SendTestNotification400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
		), nil
	case errors.Is(err, notifications.ErrUnavailable):
		s.log.Error("send test notification", "error", err)
		return gen.SendTestNotification500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not send the test message; see the server log"),
		}, nil
	default:
		// The remote status and transport error stay in the log; credentials
		// are never echoed.
		s.log.Warn("send test notification", "error", err)
		return gen.SendTestNotification502ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadGateway, "Bad Gateway",
				"a notifier did not accept the test message; check its settings and the server log"),
		), nil
	}
}

// notificationSettingsResponse maps the domain settings onto the API shape.
func notificationSettingsResponse(service *notifications.Service) gen.NotificationSettings {
	settings := service.Settings()
	return gen.NotificationSettings{
		Enabled:                 settings.Enabled,
		Threshold:               gen.NotificationThreshold(settings.Threshold),
		SlackEnabled:            settings.SlackEnabled,
		SlackConfigured:         service.SlackConfigured(),
		EmailEnabled:            settings.EmailEnabled,
		SmtpHost:                settings.SMTPHost,
		SmtpPort:                int32(settings.SMTPPort), //nolint:gosec // validated to 1..65535
		SmtpUsername:            settings.SMTPUsername,
		From:                    settings.From,
		To:                      settings.To,
		EmailPasswordConfigured: service.EmailPasswordConfigured(),
	}
}
