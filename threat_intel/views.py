"""Template views for threat intelligence management."""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Max
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

from emails.models import ExtractedIOC
from threat_intel.models import (
    BlacklistEntry, MaliciousDomain, MaliciousHash, MaliciousIP,
    WhitelistEntry, YaraRule,
)


@login_required
def threat_intel_view(request):
    """TI stats page: cards, feed status, whitelist/blacklist, recent IOCs."""
    hash_count = MaliciousHash.objects.count()
    domain_count = MaliciousDomain.objects.count()
    ip_count = MaliciousIP.objects.count()
    yara_active_count = YaraRule.objects.filter(is_active=True).count()

    feeds = [
        {
            'name': 'MalwareBazaar',
            'description': 'Malware hash database',
            'count': hash_count,
            'last_sync': MaliciousHash.objects.aggregate(last=Max('added_at'))['last'],
        },
        {
            'name': 'URLhaus',
            'description': 'Malicious URL/domain database',
            'count': domain_count,
            'last_sync': MaliciousDomain.objects.aggregate(last=Max('added_at'))['last'],
        },
    ]

    whitelist_entries = WhitelistEntry.objects.select_related('added_by').order_by('-added_at')[:50]
    blacklist_entries = BlacklistEntry.objects.select_related('added_by').order_by('-added_at')[:50]
    recent_iocs = ExtractedIOC.objects.select_related('email').order_by('-first_seen')[:20]

    is_admin = request.user.role == 'ADMIN'

    return render(request, 'threat_intel/stats.html', {
        'hash_count': hash_count,
        'domain_count': domain_count,
        'ip_count': ip_count,
        'yara_active_count': yara_active_count,
        'feeds': feeds,
        'whitelist_entries': whitelist_entries,
        'blacklist_entries': blacklist_entries,
        'recent_iocs': recent_iocs,
        'is_admin': is_admin,
        'active_page': 'threat_intel',
    })


@login_required
def threat_intel_sync_view(request):
    """POST: trigger async TI feed sync. Admin only."""
    if request.method != 'POST' or request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    from threat_intel.tasks import sync_malwarebazaar_task, sync_urlhaus_task
    sync_malwarebazaar_task.delay()
    sync_urlhaus_task.delay()
    messages.success(request, 'Threat intelligence sync tasks queued. Results will appear shortly.')
    return redirect('ti:stats')


@login_required
def whitelist_add_view(request):
    """POST: add whitelist entry. Admin only."""
    if request.method != 'POST' or request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    entry_type = request.POST.get('entry_type', '')
    value = request.POST.get('value', '').strip()
    reason = request.POST.get('reason', '').strip()

    if not value or entry_type not in ('EMAIL', 'DOMAIN', 'IP'):
        messages.error(request, 'Invalid entry type or empty value.')
        return redirect('ti:stats')

    _, created = WhitelistEntry.objects.get_or_create(
        entry_type=entry_type, value=value,
        defaults={'reason': reason, 'added_by': request.user},
    )
    if created:
        messages.success(request, f'Whitelist entry added: {entry_type} — {value}')
    else:
        messages.info(request, f'Entry already exists: {entry_type} — {value}')
    return redirect('ti:stats')


@login_required
def whitelist_remove_view(request, pk):
    """POST: remove whitelist entry. Admin only."""
    if request.method != 'POST' or request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    entry = get_object_or_404(WhitelistEntry, pk=pk)
    messages.success(request, f'Whitelist entry removed: {entry.entry_type} — {entry.value}')
    entry.delete()
    return redirect('ti:stats')


@login_required
def blacklist_add_view(request):
    """POST: add blacklist entry. Admin only."""
    if request.method != 'POST' or request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    entry_type = request.POST.get('entry_type', '')
    value = request.POST.get('value', '').strip()
    reason = request.POST.get('reason', '').strip()

    if not value or entry_type not in ('EMAIL', 'DOMAIN', 'IP'):
        messages.error(request, 'Invalid entry type or empty value.')
        return redirect('ti:stats')

    _, created = BlacklistEntry.objects.get_or_create(
        entry_type=entry_type, value=value,
        defaults={'reason': reason, 'added_by': request.user},
    )
    if created:
        messages.success(request, f'Blacklist entry added: {entry_type} — {value}')
    else:
        messages.info(request, f'Entry already exists: {entry_type} — {value}')
    return redirect('ti:stats')


@login_required
def blacklist_remove_view(request, pk):
    """POST: remove blacklist entry. Admin only."""
    if request.method != 'POST' or request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    entry = get_object_or_404(BlacklistEntry, pk=pk)
    messages.success(request, f'Blacklist entry removed: {entry.entry_type} — {entry.value}')
    entry.delete()
    return redirect('ti:stats')
