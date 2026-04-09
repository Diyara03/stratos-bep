from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('', views.report_list_view, name='list'),
    path('export/emails/', views.email_summary_export, name='email-summary-export'),
    path('export/iocs/', views.ioc_export_view, name='ioc-export'),
    path('export/ti-stats/', views.ti_stats_export, name='ti-stats-export'),
    path('scheduled/<int:pk>/toggle/', views.scheduled_report_toggle, name='scheduled-toggle'),
]
