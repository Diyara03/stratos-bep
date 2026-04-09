from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('users/', views.user_list_view, name='user-list'),
    path('users/<int:pk>/edit-role/', views.user_edit_role_view, name='user-edit-role'),
    path('users/<int:pk>/toggle-active/', views.user_toggle_active_view, name='user-toggle-active'),
    path('users/add/', views.user_add_view, name='user-add'),
]
