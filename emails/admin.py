from django.contrib import admin

from .models import (
    AnalysisResult,
    Email,
    EmailAttachment,
    ExtractedIOC,
    QuarantineEntry,
    SystemConfig,
)


@admin.register(Email)
class EmailAdmin(admin.ModelAdmin):
    list_display = ('id', 'from_address', 'subject', 'verdict', 'score', 'status', 'received_at')
    list_filter = ('verdict', 'status')
    search_fields = ('from_address', 'subject')


@admin.register(EmailAttachment)
class EmailAttachmentAdmin(admin.ModelAdmin):
    list_display = ('email', 'filename', 'sha256_hash', 'is_dangerous_ext', 'ti_match')
    list_filter = ('is_dangerous_ext',)
    search_fields = ('filename', 'sha256_hash')


@admin.register(AnalysisResult)
class AnalysisResultAdmin(admin.ModelAdmin):
    list_display = ('email', 'total_score', 'spf_result', 'keyword_score')
    list_filter = ('spf_result',)


@admin.register(QuarantineEntry)
class QuarantineEntryAdmin(admin.ModelAdmin):
    list_display = ('email', 'status', 'reviewer', 'reviewed_at')
    list_filter = ('status',)


@admin.register(ExtractedIOC)
class ExtractedIOCAdmin(admin.ModelAdmin):
    list_display = ('email', 'ioc_type', 'value', 'severity')
    list_filter = ('ioc_type', 'severity')
    search_fields = ('value',)


admin.site.register(SystemConfig)
