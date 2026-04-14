FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=stratos_server.settings.prod

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    libjansson-dev \
    libmagic1 \
    build-essential \
    curl \
    automake \
    libtool \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Collect static files at build time
RUN python manage.py collectstatic --noinput 2>/dev/null || true

EXPOSE 8000

CMD ["gunicorn", "stratos_server.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120"]
