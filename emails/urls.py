from django.urls import path

from . import api_views

urlpatterns = [
    path('emails/', api_views.EmailListView.as_view(), name='email-list'),
    path('emails/<int:pk>/', api_views.EmailDetailView.as_view(), name='email-detail'),
    path('quarantine/', api_views.QuarantineListView.as_view(), name='quarantine-list'),
    path('quarantine/<int:pk>/action/', api_views.QuarantineActionView.as_view(), name='quarantine-action'),
    path('dashboard/stats/', api_views.DashboardStatsView.as_view(), name='dashboard-stats'),
]
