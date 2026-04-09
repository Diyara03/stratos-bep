from django.contrib import admin

from .models import IOCExport, Report, ScheduledReport


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('report_type', 'generated_by', 'output_format', 'record_count', 'created_at')
    list_filter = ('report_type', 'output_format')


@admin.register(ScheduledReport)
class ScheduledReportAdmin(admin.ModelAdmin):
    list_display = ('report_type', 'schedule', 'is_active', 'next_run')
    list_filter = ('schedule', 'is_active')


@admin.register(IOCExport)
class IOCExportAdmin(admin.ModelAdmin):
    list_display = ('export_format', 'record_count', 'created_by', 'created_at')
    list_filter = ('export_format',)
