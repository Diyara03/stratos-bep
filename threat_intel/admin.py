from django.contrib import admin

from .models import (
    BlacklistEntry,
    MaliciousDomain,
    MaliciousHash,
    MaliciousIP,
    WhitelistEntry,
    YaraRule,
)


@admin.register(MaliciousHash)
class MaliciousHashAdmin(admin.ModelAdmin):
    list_display = ('sha256_hash', 'malware_family', 'source', 'severity', 'added_at')
    list_filter = ('source', 'severity')
    search_fields = ('sha256_hash', 'malware_family')


@admin.register(MaliciousDomain)
class MaliciousDomainAdmin(admin.ModelAdmin):
    list_display = ('domain', 'category', 'source', 'added_at')
    list_filter = ('source',)
    search_fields = ('domain',)


@admin.register(MaliciousIP)
class MaliciousIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'category', 'abuse_score', 'added_at')
    list_filter = ('source',)
    search_fields = ('ip_address',)


@admin.register(YaraRule)
class YaraRuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'severity', 'is_active', 'added_at')
    list_filter = ('severity', 'is_active')
    search_fields = ('name',)


@admin.register(WhitelistEntry)
class WhitelistEntryAdmin(admin.ModelAdmin):
    list_display = ('entry_type', 'value', 'reason', 'added_by')
    list_filter = ('entry_type',)
    search_fields = ('value',)


@admin.register(BlacklistEntry)
class BlacklistEntryAdmin(admin.ModelAdmin):
    list_display = ('entry_type', 'value', 'reason', 'added_by')
    list_filter = ('entry_type',)
    search_fields = ('value',)
