"""Template views for user management."""
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

User = get_user_model()


@login_required
def user_list_view(request):
    """User management page. Admin only."""
    if request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    users = User.objects.all().order_by('username')
    return render(request, 'accounts/users.html', {
        'users': users,
        'role_choices': User.ROLE_CHOICES,
        'active_page': 'users',
    })


@login_required
def user_edit_role_view(request, pk):
    """POST: change user role. Admin only."""
    if request.method != 'POST' or request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    target = get_object_or_404(User, pk=pk)
    new_role = request.POST.get('role', '')

    # Prevent self-demotion
    if target == request.user:
        messages.error(request, 'You cannot change your own role.')
        return redirect('accounts:user-list')

    valid_roles = [c[0] for c in User.ROLE_CHOICES]
    if new_role not in valid_roles:
        messages.error(request, f'Invalid role: {new_role}')
        return redirect('accounts:user-list')

    target.role = new_role
    target.save(update_fields=['role'])
    messages.success(request, f'Role for {target.username} changed to {new_role}.')
    return redirect('accounts:user-list')


@login_required
def user_toggle_active_view(request, pk):
    """POST: activate/deactivate user. Admin only."""
    if request.method != 'POST' or request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    target = get_object_or_404(User, pk=pk)

    # Prevent self-deactivation
    if target == request.user:
        messages.error(request, 'You cannot deactivate your own account.')
        return redirect('accounts:user-list')

    target.is_active = not target.is_active
    target.save(update_fields=['is_active'])
    action = 'activated' if target.is_active else 'deactivated'
    messages.success(request, f'User {target.username} {action}.')
    return redirect('accounts:user-list')


@login_required
def user_add_view(request):
    """POST: create new user. Admin only."""
    if request.method != 'POST' or request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    username = request.POST.get('username', '').strip()
    email = request.POST.get('email', '').strip()
    password = request.POST.get('password', '')
    role = request.POST.get('role', 'VIEWER')

    if not username or not password:
        messages.error(request, 'Username and password are required.')
        return redirect('accounts:user-list')

    valid_roles = [c[0] for c in User.ROLE_CHOICES]
    if role not in valid_roles:
        role = 'VIEWER'

    if User.objects.filter(username=username).exists():
        messages.error(request, f'Username "{username}" already exists.')
        return redirect('accounts:user-list')

    User.objects.create_user(username=username, email=email, password=password, role=role)
    messages.success(request, f'User {username} created with role {role}.')
    return redirect('accounts:user-list')
