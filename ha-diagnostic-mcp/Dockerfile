FROM python:3.12-alpine

LABEL \
  io.hass.version="0.1.2" \
  io.hass.type="app" \
  io.hass.arch="aarch64|amd64"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
CMD ["python", "-m", "app.main"]
