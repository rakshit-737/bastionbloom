FROM python:3.12-slim
RUN useradd --uid 10001 --create-home appuser
WORKDIR /home/appuser
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "http.server", "8080"]
