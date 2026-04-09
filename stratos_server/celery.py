import os

from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'stratos_server.settings.dev')

app = Celery('stratos_server')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
