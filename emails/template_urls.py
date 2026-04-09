from django.urls import path
from . import views

app_name = 'ui'

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('emails/', views.email_list_view, name='email-list'),
    path('emails/<int:pk>/', views.email_detail_view, name='email-detail'),
    path('quarantine/', views.quarantine_list_view, name='quarantine-list'),
    path('quarantine/<int:pk>/action/', views.quarantine_action_view, name='quarantine-action'),
    path('iocs/', views.ioc_list_view, name='ioc-list'),
]
