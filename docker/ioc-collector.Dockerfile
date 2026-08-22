# TALON IOC Collector - Docker Image
#
# This image pre-installs all of the project's Python dependencies.
# When running, the host directory is mounted as /app (see: deploy.sh),
# so code changes are reflected without needing to rebuild the image.

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "cli.py"]
CMD ["--init-db", "--fetch", "--export", "wazuh"]
