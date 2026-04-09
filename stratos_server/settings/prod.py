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
        'HOST': os.environ.get('DATABASE_URL', 'localhost').split('@')[-1].split(':')[0] if os.environ.get('DATABASE_URL') else 'localhost',
        'PORT': os.environ.get('DATABASE_URL', ':5432/').split(':')[-1].split('/')[0] if os.environ.get('DATABASE_URL') else '5432',
    }
}
