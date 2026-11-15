package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ozerozdas/bastion/internal/docker"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// GetDockerImages implements gen.StrictServerInterface. A missing daemon is a
// normal state, not an error: the response is 200 with available=false and an
// empty list, so the UI can hide the Docker source instead of reporting a
// failure.
func (s *Server) GetDockerImages(ctx context.Context, _ gen.GetDockerImagesRequestObject) (gen.GetDockerImagesResponseObject, error) {
	status := docker.Status(ctx)
	out := gen.DockerImageList{
		Available: status.Found,
		Host:      status.Host,
		Images:    []gen.DockerImage{},
	}
	if !status.Found {
		return gen.GetDockerImages200JSONResponse(out), nil
	}

	list, err := docker.ListImages(ctx)
	if errors.Is(err, docker.ErrUnavailable) {
		return gen.GetDockerImages200JSONResponse(out), nil
	}
	if err != nil {
		s.log.Error("list docker images", "error", err)
		return gen.GetDockerImages500ApplicationProblemPlusJSONResponse{Body: newProblem(
			http.StatusInternalServerError, "Internal Server Error",
			"could not list the local Docker images; see the server log")}, nil
	}

	out.Images = make([]gen.DockerImage, 0, len(list))
	for _, image := range list {
		out.Images = append(out.Images, gen.DockerImage{
			Reference: image.Reference,
			Id:        image.ID,
			SizeBytes: image.Size,
			CreatedAt: image.Created,
		})
	}
	return gen.GetDockerImages200JSONResponse(out), nil
}
