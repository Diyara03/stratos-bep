from django.db import connection
from django.http import JsonResponse


def health(request):
    """Health check endpoint for Docker and monitoring."""
    data = {
        'status': 'ok',
        'version': '0.1.0',
        'db': 'connected',
    }
    try:
        connection.ensure_connection()
    except Exception:
        data['status'] = 'degraded'
        data['db'] = 'unavailable'
        return JsonResponse(data, status=503)
    return JsonResponse(data, status=200)
