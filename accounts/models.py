from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    ROLE_CHOICES = [
        ('ADMIN', 'Admin'),
        ('ANALYST', 'Analyst'),
        ('VIEWER', 'Viewer'),
    ]

    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='VIEWER')
    department = models.CharField(max_length=100, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        db_table = 'stratos_user'

    def __str__(self):
        return f'{self.username} ({self.role})'
