"""
Test settings for Stratos BEP.
Uses SQLite, disables Celery eager execution, and minimizes I/O.
Run tests with: python manage.py test --settings=stratos_server.settings.test
"""
from .base import *  # noqa: F401, F403

DEBUG = False

ALLOWED_HOSTS = ['*']

# SQLite for fast, zero-dependency tests
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Celery: run tasks synchronously in tests
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

# Faster password hashing in tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Disable logging noise during tests
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {'null': {'class': 'logging.NullHandler'}},
    'root': {'handlers': ['null']},
}
