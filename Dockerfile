# Nothing is installed and nothing is copied in: the image is the stock
# interpreter, the source is bind-mounted read-only at /app, and all writable
# state lives on the /data volume. That is deliberate -- a monitoring tool that
# needs a build to change a target list is a monitoring tool nobody updates.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python3", "/app/server.py"]
