"""ASGI config for stratos_server project."""
import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'stratos_server.settings.dev')

application = get_asgi_application()
