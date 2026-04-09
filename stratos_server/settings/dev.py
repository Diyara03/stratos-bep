"""
Development settings for Stratos BEP.
Uses SQLite when DATABASE_URL is not set.
"""
import os

from .base import *  # noqa: F401, F403

DEBUG = True

ALLOWED_HOSTS = ['*']

DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get('POSTGRES_DB', 'stratos'),
            'USER': os.environ.get('POSTGRES_USER', 'stratos'),
            'PASSWORD': os.environ.get('POSTGRES_PASSWORD', 'stratos_dev_pw'),
            'HOST': DATABASE_URL.split('@')[1].split(':')[0] if '@' in DATABASE_URL else 'localhost',
            'PORT': DATABASE_URL.split(':')[-1].split('/')[0] if DATABASE_URL else '5432',
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
