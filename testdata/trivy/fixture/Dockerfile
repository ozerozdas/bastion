# Fixture for the BST-003 Trivy spike: deliberately misconfigured.
# Expected misconfiguration checks:
#   - image tag ":latest" is used
#   - no USER instruction, so the container runs as root
FROM ubuntu:latest

RUN apt-get update && apt-get install -y curl

COPY . /app

CMD ["/app/run.sh"]
