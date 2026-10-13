FROM python:3.11-slim

# Keep Python output unbuffered and skip .pyc files in the container.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first to take advantage of Docker layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Store the SQLite database on a path that can be backed by a mounted volume
# so data survives container restarts/redeploys.
ENV DATABASE=/data/users.db
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 5000

# PORT is respected by platforms that inject it; defaults to 5000 otherwise.
# 2 workers x 8 threads serve 16 requests at once, so a slow email/SMS send or
# a big upload doesn't block other users. With threaded workers the timeout
# only catches a hung worker, not a long upload. --preload sets up the database
# once before the workers start.
CMD ["sh", "-c", "exec gunicorn app:app --bind 0.0.0.0:${PORT:-5000} --worker-class gthread --workers ${WEB_CONCURRENCY:-2} --threads 8 --timeout 120 --preload"]
