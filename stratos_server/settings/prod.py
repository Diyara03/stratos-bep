"""
Production settings for Stratos BEP.
Requires DATABASE_URL and proper SECRET_KEY.
"""
import os

from .base import *  # noqa: F401, F403

DEBUG = False

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRES_DB', 'stratos'),
        'USER': os.environ.get('POSTGRES_USER', 'stratos'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD', ''),
        'HOST': os.environ.get('POSTGRES_HOST', 'postgres'),
        'PORT': os.environ.get('POSTGRES_PORT', '5432'),
    }
}

# Static files: whitenoise serves them without nginx
MIDDLEWARE = [MIDDLEWARE[0], 'whitenoise.middleware.WhiteNoiseMiddleware'] + MIDDLEWARE[1:]  # noqa: F405
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get('CSRF_TRUSTED_ORIGINS', '').split(',')
    if origin.strip()
]

# Session security
SESSION_COOKIE_SECURE = os.environ.get('HTTPS_ENABLED', 'false').lower() == 'true'
CSRF_COOKIE_SECURE = os.environ.get('HTTPS_ENABLED', 'false').lower() == 'true'
