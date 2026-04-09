from django.urls import path
from . import views

app_name = 'ti'

urlpatterns = [
    path('', views.threat_intel_view, name='stats'),
    path('sync/', views.threat_intel_sync_view, name='sync'),
    path('whitelist/add/', views.whitelist_add_view, name='whitelist-add'),
    path('whitelist/<int:pk>/remove/', views.whitelist_remove_view, name='whitelist-remove'),
    path('blacklist/add/', views.blacklist_add_view, name='blacklist-add'),
    path('blacklist/<int:pk>/remove/', views.blacklist_remove_view, name='blacklist-remove'),
]
