# Static fixture for mutable-image, remote-download, and root-user checks.
FROM python:latest
ADD https://example.invalid/unverified-application.tar.gz /app/
WORKDIR /app
USER root
CMD ["python", "-m", "http.server", "8080"]
