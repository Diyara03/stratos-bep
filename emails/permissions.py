"""
Custom DRF permissions for Stratos BEP.
"""
from rest_framework.permissions import BasePermission


class IsAnalystOrAbove(BasePermission):
    """Allow access only to users with ADMIN or ANALYST role."""

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.role in ('ADMIN', 'ANALYST')
        )
