from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('health/', views.health, name='health'),
    path('api/', include('emails.urls')),
    path('accounts/login/', auth_views.LoginView.as_view(), name='login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(next_page='/accounts/login/'), name='logout'),
    # Phase 7
    path('threat-intel/', include('threat_intel.template_urls')),
    path('reports/', include('reports.template_urls')),
    path('', include('accounts.template_urls')),
    # Phase 6 (catch-all, must be last)
    path('', include('emails.template_urls')),
]
