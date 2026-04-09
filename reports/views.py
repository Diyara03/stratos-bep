"""Template views for reports and data export."""
import csv
import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from emails.models import Email, ExtractedIOC
from reports.models import IOCExport, Report, ScheduledReport
from threat_intel.models import MaliciousDomain, MaliciousHash, MaliciousIP, YaraRule


@login_required
def report_list_view(request):
    """Reports page: export buttons, report history, scheduled reports."""
    reports = Report.objects.select_related('generated_by').order_by('-created_at')[:50]
    scheduled_reports = ScheduledReport.objects.select_related('created_by').all()
    is_admin = request.user.role == 'ADMIN'
    can_export = request.user.role in ('ADMIN', 'ANALYST')

    return render(request, 'reports/list.html', {
        'reports': reports,
        'scheduled_reports': scheduled_reports,
        'is_admin': is_admin,
        'can_export': can_export,
        'active_page': 'reports',
    })


@login_required
def email_summary_export(request):
    """Generate CSV export of email summary. Analyst+ only."""
    if request.user.role not in ('ADMIN', 'ANALYST'):
        return HttpResponseForbidden('Analyst or Admin access required.')

    qs = Email.objects.all().order_by('-received_at')

    # Apply optional filters
    verdict = request.GET.get('verdict', '')
    status = request.GET.get('status', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')

    filters_applied = {}
    if verdict:
        qs = qs.filter(verdict=verdict)
        filters_applied['verdict'] = verdict
    if status:
        qs = qs.filter(status=status)
        filters_applied['status'] = status
    if date_from:
        qs = qs.filter(received_at__date__gte=date_from)
        filters_applied['date_from'] = date_from
    if date_to:
        qs = qs.filter(received_at__date__lte=date_to)
        filters_applied['date_to'] = date_to

    now = timezone.now()
    filename = f'email_summary_{now.strftime("%Y%m%d_%H%M%S")}.csv'

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)
    writer.writerow([
        'ID', 'Message ID', 'From', 'Subject', 'Verdict', 'Score',
        'Confidence', 'Status', 'Received At', 'Analyzed At', 'Pipeline Duration (ms)',
    ])

    count = 0
    for email in qs.iterator():
        pipeline_ms = ''
        try:
            pipeline_ms = email.analysis.pipeline_duration_ms or ''
        except Exception:
            pass

        writer.writerow([
            email.id, email.message_id, email.from_address, email.subject,
            email.verdict or '', email.score or '', email.confidence or '',
            email.status, email.received_at.isoformat() if email.received_at else '',
            email.analyzed_at.isoformat() if email.analyzed_at else '', pipeline_ms,
        ])
        count += 1

    # Create Report audit record
    Report.objects.create(
        report_type='EMAIL_SUMMARY',
        generated_by=request.user,
        output_format='CSV',
        filters_applied=filters_applied,
        record_count=count,
    )

    return response


@login_required
def ioc_export_view(request):
    """Generate CSV export of extracted IOCs. Analyst+ only."""
    if request.user.role not in ('ADMIN', 'ANALYST'):
        return HttpResponseForbidden('Analyst or Admin access required.')

    qs = ExtractedIOC.objects.select_related('email').order_by('-first_seen')

    now = timezone.now()
    filename = f'ioc_export_{now.strftime("%Y%m%d_%H%M%S")}.csv'

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)
    writer.writerow([
        'IOC Type', 'Value', 'Severity', 'Source Checker',
        'Email Subject', 'Email From', 'First Seen',
    ])

    count = 0
    for ioc in qs.iterator():
        writer.writerow([
            ioc.ioc_type, ioc.value, ioc.severity, ioc.source_checker,
            ioc.email.subject if ioc.email else '',
            ioc.email.from_address if ioc.email else '',
            ioc.first_seen.isoformat(),
        ])
        count += 1

    # Create IOCExport audit record
    IOCExport.objects.create(
        export_format='CSV',
        ioc_types=['HASH', 'URL', 'IP', 'DOMAIN'],
        record_count=count,
        created_by=request.user,
    )

    return response


@login_required
def ti_stats_export(request):
    """Generate JSON export of TI statistics. Admin only."""
    if request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    now = timezone.now()

    data = {
        'exported_at': now.isoformat(),
        'malicious_hashes': {
            'total': MaliciousHash.objects.count(),
            'by_source': dict(
                MaliciousHash.objects.values_list('source').annotate(c=Count('id')).values_list('source', 'c')
            ),
            'sample': list(MaliciousHash.objects.values_list('sha256_hash', flat=True)[:5]),
        },
        'malicious_domains': {
            'total': MaliciousDomain.objects.count(),
            'by_source': dict(
                MaliciousDomain.objects.values_list('source').annotate(c=Count('id')).values_list('source', 'c')
            ),
            'sample': list(MaliciousDomain.objects.values_list('domain', flat=True)[:5]),
        },
        'malicious_ips': {
            'total': MaliciousIP.objects.count(),
        },
        'yara_rules': {
            'total': YaraRule.objects.count(),
            'active': YaraRule.objects.filter(is_active=True).count(),
            'names': list(YaraRule.objects.values_list('name', flat=True)),
        },
    }

    filename = f'ti_stats_{now.strftime("%Y%m%d_%H%M%S")}.json'
    response = HttpResponse(
        json.dumps(data, indent=2, default=str),
        content_type='application/json',
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    # Create Report audit record
    Report.objects.create(
        report_type='THREAT_INTEL',
        generated_by=request.user,
        output_format='JSON',
        record_count=sum([
            data['malicious_hashes']['total'],
            data['malicious_domains']['total'],
            data['malicious_ips']['total'],
            data['yara_rules']['total'],
        ]),
    )

    return response


@login_required
def scheduled_report_toggle(request, pk):
    """POST: toggle scheduled report active status. Admin only."""
    if request.method != 'POST' or request.user.role != 'ADMIN':
        return HttpResponseForbidden('Admin access required.')

    sr = get_object_or_404(ScheduledReport, pk=pk)
    sr.is_active = not sr.is_active
    sr.save(update_fields=['is_active'])
    status_text = 'activated' if sr.is_active else 'deactivated'
    messages.success(request, f'Scheduled report {sr.report_type} {status_text}.')
    return redirect('reports:list')
