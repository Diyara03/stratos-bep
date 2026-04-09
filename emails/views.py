"""Template views for the Stratos BEP dashboard UI."""
import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, Max, Q
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from emails.models import Email, AnalysisResult, ExtractedIOC, QuarantineEntry
from threat_intel.models import BlacklistEntry, MaliciousDomain, MaliciousHash


@login_required
def dashboard_view(request):
    """Dashboard with stats cards and recent alerts."""
    today = timezone.now().date()

    total_emails = Email.objects.count()
    clean_count = Email.objects.filter(verdict='CLEAN').count()
    suspicious_count = Email.objects.filter(verdict='SUSPICIOUS').count()
    malicious_count = Email.objects.filter(verdict='MALICIOUS').count()
    pending_count = Email.objects.filter(status='PENDING').count()
    quarantine_pending = QuarantineEntry.objects.filter(status='PENDING').count()
    ti_hashes = MaliciousHash.objects.count()
    ti_domains = MaliciousDomain.objects.count()
    last_sync = MaliciousHash.objects.aggregate(last=Max('added_at'))['last']

    recent_alerts = (
        Email.objects.filter(verdict__in=['SUSPICIOUS', 'MALICIOUS'])
        .order_by('-received_at')[:10]
    )

    stats = {
        'total_emails': total_emails,
        'clean_count': clean_count,
        'suspicious_count': suspicious_count,
        'malicious_count': malicious_count,
        'pending_count': pending_count,
        'quarantine_pending': quarantine_pending,
        'ti_hashes': ti_hashes,
        'ti_domains': ti_domains,
        'last_sync': last_sync,
    }

    return render(request, 'dashboard/index.html', {
        'stats': stats,
        'recent_alerts': recent_alerts,
        'active_page': 'dashboard',
    })


@login_required
def email_list_view(request):
    """Filterable, paginated email list."""
    qs = Email.objects.all().order_by('-received_at')

    verdict = request.GET.get('verdict', '')
    status = request.GET.get('status', '')
    from_addr = request.GET.get('from_address', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')

    if verdict:
        qs = qs.filter(verdict=verdict)
    if status:
        qs = qs.filter(status=status)
    if from_addr:
        qs = qs.filter(from_address__icontains=from_addr)
    if date_from:
        qs = qs.filter(received_at__date__gte=date_from)
    if date_to:
        qs = qs.filter(received_at__date__lte=date_to)

    paginator = Paginator(qs, 20)
    page_obj = paginator.get_page(request.GET.get('page'))

    filters = {
        'verdict': verdict,
        'status': status,
        'from_address': from_addr,
        'date_from': date_from,
        'date_to': date_to,
    }

    return render(request, 'emails/list.html', {
        'page_obj': page_obj,
        'filters': filters,
        'active_page': 'emails',
    })


@login_required
def email_detail_view(request, pk):
    """Email detail with analysis tabs."""
    email = get_object_or_404(
        Email.objects.select_related('analysis').prefetch_related('attachments', 'iocs'),
        pk=pk,
    )
    can_view_raw = request.user.role in ('ADMIN', 'ANALYST')

    # Prepare analysis data for JSON display
    analysis_json = None
    if can_view_raw and hasattr(email, 'analysis'):
        a = email.analysis
        analysis_json = json.dumps({
            'preprocess_score': a.preprocess_score,
            'spf_result': a.spf_result,
            'dkim_result': a.dkim_result,
            'dmarc_result': a.dmarc_result,
            'is_reply_to_mismatch': a.is_reply_to_mismatch,
            'is_display_spoof': a.is_display_spoof,
            'keyword_score': a.keyword_score,
            'keywords_matched': a.keywords_matched,
            'url_score': a.url_score,
            'url_findings': a.url_findings,
            'attachment_score': a.attachment_score,
            'attachment_findings': a.attachment_findings,
            'chain_score': a.chain_score,
            'chain_findings': a.chain_findings,
            'total_score': a.total_score,
            'pipeline_duration_ms': a.pipeline_duration_ms,
        }, indent=2)

    return render(request, 'emails/detail.html', {
        'email': email,
        'can_view_raw': can_view_raw,
        'analysis_json': analysis_json,
        'active_page': 'emails',
    })


@login_required
def quarantine_list_view(request):
    """Quarantine management list."""
    qs = (
        QuarantineEntry.objects.select_related('email', 'reviewer')
        .filter(email__status__in=['QUARANTINED', 'BLOCKED'])
        .order_by('-created_at')
    )

    status_filter = request.GET.get('status', '')
    if status_filter:
        qs = qs.filter(status=status_filter)

    paginator = Paginator(qs, 20)
    page_obj = paginator.get_page(request.GET.get('page'))
    can_act = request.user.role in ('ADMIN', 'ANALYST')

    return render(request, 'quarantine/list.html', {
        'page_obj': page_obj,
        'can_act': can_act,
        'status_filter': status_filter,
        'active_page': 'quarantine',
    })


@login_required
def quarantine_action_view(request, pk):
    """Handle quarantine release/block/delete actions."""
    if request.method != 'POST':
        return redirect('ui:quarantine-list')

    if request.user.role not in ('ADMIN', 'ANALYST'):
        return HttpResponseForbidden('Insufficient permissions.')

    entry = get_object_or_404(
        QuarantineEntry.objects.select_related('email'), pk=pk
    )
    action = request.POST.get('action')
    notes = request.POST.get('notes', '')

    if action == 'release':
        entry.status = 'RELEASED'
        entry.action = 'release'
        entry.reviewer = request.user
        entry.reviewed_at = timezone.now()
        entry.notes = notes
        entry.save()
        entry.email.status = 'DELIVERED'
        entry.email.save(update_fields=['status'])
        messages.success(request, f'Email from {entry.email.from_address} released.')

    elif action == 'block':
        entry.status = 'BLOCKED'
        entry.action = 'block'
        entry.reviewer = request.user
        entry.reviewed_at = timezone.now()
        entry.notes = notes
        entry.save()
        entry.email.status = 'BLOCKED'
        entry.email.save(update_fields=['status'])
        # Add sender to blacklist
        BlacklistEntry.objects.get_or_create(
            entry_type='EMAIL',
            value=entry.email.from_address,
            defaults={'reason': f'Blocked via quarantine action. {notes}'.strip(), 'added_by': request.user},
        )
        messages.success(request, f'Sender {entry.email.from_address} blocked.')

    elif action == 'delete':
        from_addr = entry.email.from_address
        entry.email.delete()  # Cascades to entry, attachments, IOCs, analysis
        messages.success(request, f'Email from {from_addr} permanently deleted.')

    else:
        messages.error(request, 'Invalid action.')

    return redirect('ui:quarantine-list')


@login_required
def ioc_list_view(request):
    """Filterable, paginated IOC list."""
    qs = ExtractedIOC.objects.select_related('email').order_by('-first_seen')

    ioc_type = request.GET.get('ioc_type', '')
    severity = request.GET.get('severity', '')

    if ioc_type:
        qs = qs.filter(ioc_type=ioc_type)
    if severity:
        qs = qs.filter(severity=severity)

    paginator = Paginator(qs, 20)
    page_obj = paginator.get_page(request.GET.get('page'))

    filters = {'ioc_type': ioc_type, 'severity': severity}
    can_export = request.user.role in ('ADMIN', 'ANALYST')

    return render(request, 'emails/iocs.html', {
        'page_obj': page_obj,
        'filters': filters,
        'can_export': can_export,
        'active_page': 'iocs',
    })
