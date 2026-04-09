"""WSGI config for stratos_server project."""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'stratos_server.settings.dev')

application = get_wsgi_application()
