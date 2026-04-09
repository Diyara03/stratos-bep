from django.conf import settings
from django.db import models


class Report(models.Model):
    REPORT_TYPE_CHOICES = [
        ('EMAIL_SUMMARY', 'Email Summary'),
        ('THREAT_INTEL', 'Threat Intel'),
        ('IOC_EXPORT', 'IOC Export'),
        ('CUSTOM', 'Custom'),
    ]
    FORMAT_CHOICES = [
        ('CSV', 'CSV'),
        ('JSON', 'JSON'),
        ('PDF', 'PDF'),
    ]

    report_type = models.CharField(max_length=30, choices=REPORT_TYPE_CHOICES)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    file_path = models.CharField(max_length=500, blank=True)
    output_format = models.CharField(
        max_length=10, choices=FORMAT_CHOICES, default='CSV'
    )
    filters_applied = models.JSONField(default=dict)
    record_count = models.IntegerField(default=0)
    file_size_bytes = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"{self.report_type} report -- {self.created_at.date()}"


class ScheduledReport(models.Model):
    REPORT_TYPE_CHOICES = [
        ('EMAIL_SUMMARY', 'Email Summary'),
        ('THREAT_INTEL', 'Threat Intel'),
        ('IOC_EXPORT', 'IOC Export'),
        ('CUSTOM', 'Custom'),
    ]
    SCHEDULE_CHOICES = [
        ('DAILY', 'Daily'),
        ('WEEKLY', 'Weekly'),
        ('MONTHLY', 'Monthly'),
    ]

    report_type = models.CharField(max_length=30, choices=REPORT_TYPE_CHOICES)
    schedule = models.CharField(max_length=10, choices=SCHEDULE_CHOICES)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True, db_index=True)
    is_active = models.BooleanField(default=True)
    recipients = models.JSONField(default=list)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.schedule} {self.report_type}"


class IOCExport(models.Model):
    FORMAT_CHOICES = [
        ('CSV', 'CSV'),
        ('JSON', 'JSON'),
        ('STIX', 'STIX'),
    ]

    export_format = models.CharField(
        max_length=10, choices=FORMAT_CHOICES, default='CSV'
    )
    ioc_types = models.JSONField(default=list)
    record_count = models.IntegerField(default=0)
    file_path = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"IOC Export {self.export_format} -- {self.record_count} records"
