"""Seed database with demo data for UI development and screenshots."""
import random
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils import timezone

from emails.models import AnalysisResult, Email, EmailAttachment, ExtractedIOC, QuarantineEntry
from threat_intel.models import MaliciousDomain, MaliciousHash

User = get_user_model()


class Command(BaseCommand):
    help = 'Seed database with demo emails for UI screenshots'

    def add_arguments(self, parser):
        parser.add_argument('--flush', action='store_true', help='Clear existing demo data first')

    def handle(self, *args, **options):
        if options['flush']:
            Email.objects.filter(message_id__startswith='demo-').delete()
            self.stdout.write('Flushed existing demo data.')

        # Users
        admin, _ = User.objects.get_or_create(
            username='admin',
            defaults={'email': 'admin@stratos.local', 'role': 'ADMIN', 'is_staff': True, 'is_superuser': True},
        )
        if _:
            admin.set_password('admin123')
            admin.save()

        analyst, _ = User.objects.get_or_create(
            username='analyst',
            defaults={'email': 'analyst@stratos.local', 'role': 'ANALYST'},
        )
        if _:
            analyst.set_password('analyst123')
            analyst.save()

        viewer, _ = User.objects.get_or_create(
            username='viewer',
            defaults={'email': 'viewer@stratos.local', 'role': 'VIEWER'},
        )
        if _:
            viewer.set_password('viewer123')
            viewer.save()

        self.stdout.write(f'Users: admin, analyst, viewer')

        # TI records
        MaliciousHash.objects.get_or_create(
            sha256_hash='a' * 64,
            defaults={'malware_family': 'DemoRAT', 'source': 'MALWAREBAZAAR', 'severity': 'HIGH'},
        )
        MaliciousHash.objects.get_or_create(
            sha256_hash='b' * 64,
            defaults={'malware_family': 'PhishKit.A', 'source': 'VIRUSTOTAL', 'severity': 'CRITICAL'},
        )
        MaliciousDomain.objects.get_or_create(
            domain='phishing-demo.xyz',
            defaults={'category': 'phishing', 'source': 'URLHAUS'},
        )
        MaliciousDomain.objects.get_or_create(
            domain='malware-c2.ru',
            defaults={'category': 'c2', 'source': 'URLHAUS'},
        )
        self.stdout.write(f'TI: {MaliciousHash.objects.count()} hashes, {MaliciousDomain.objects.count()} domains')

        # Sample emails
        samples = [
            # CLEAN
            dict(message_id='demo-clean-001', from_address='alice@company.com', from_display_name='Alice Johnson',
                 subject='Q4 Budget Report - Final Version', verdict='CLEAN', score=5, status='DELIVERED',
                 confidence='HIGH', spf='pass', dkim='pass', dmarc='pass', kw_score=0, url_score=0, att_score=0),
            dict(message_id='demo-clean-002', from_address='bob@partner.org', from_display_name='Bob Williams',
                 subject='Meeting tomorrow at 3pm', verdict='CLEAN', score=8, status='DELIVERED',
                 confidence='HIGH', spf='pass', dkim='pass', dmarc='pass', kw_score=0, url_score=0, att_score=0),
            dict(message_id='demo-clean-003', from_address='hr@company.com', from_display_name='HR Department',
                 subject='Holiday schedule 2026', verdict='CLEAN', score=3, status='DELIVERED',
                 confidence='HIGH', spf='pass', dkim='pass', dmarc='pass', kw_score=0, url_score=0, att_score=0),
            # SUSPICIOUS
            dict(message_id='demo-susp-001', from_address='billing@paypa1.com', from_display_name='PayPal Billing',
                 subject='Urgent: Verify your account immediately', verdict='SUSPICIOUS', score=45, status='QUARANTINED',
                 confidence='MEDIUM', spf='softfail', dkim='fail', dmarc='fail', kw_score=10, url_score=15, att_score=0),
            dict(message_id='demo-susp-002', from_address='security@bank-alert.net', from_display_name='Bank Security',
                 subject='Security alert: Unusual activity detected', verdict='SUSPICIOUS', score=52, status='QUARANTINED',
                 confidence='LOW', spf='fail', dkim='fail', dmarc='fail', kw_score=12, url_score=20, att_score=0),
            dict(message_id='demo-susp-003', from_address='noreply@invoice-portal.xyz', from_display_name='Invoice Portal',
                 subject='Invoice attached - wire transfer required', verdict='SUSPICIOUS', score=38, status='QUARANTINED',
                 confidence='MEDIUM', spf='softfail', dkim='none', dmarc='none', kw_score=8, url_score=10, att_score=5),
            # MALICIOUS
            dict(message_id='demo-mal-001', from_address='attacker@suspicious-domain.xyz', from_display_name='Account Team',
                 subject='Urgent: Confirm your identity - account suspended', verdict='MALICIOUS', score=85, status='BLOCKED',
                 confidence='HIGH', spf='fail', dkim='fail', dmarc='fail', kw_score=18, url_score=30, att_score=20),
            dict(message_id='demo-mal-002', from_address='hr-dept@company-payroll.ru', from_display_name='HR Payroll',
                 subject='Bitcoin payment - confidential request', verdict='MALICIOUS', score=92, status='BLOCKED',
                 confidence='HIGH', spf='fail', dkim='fail', dmarc='fail', kw_score=16, url_score=25, att_score=35),
            dict(message_id='demo-mal-003', from_address='support@micros0ft-security.com', from_display_name='Microsoft Support',
                 subject='Important security update - click here immediately', verdict='MALICIOUS', score=78, status='BLOCKED',
                 confidence='HIGH', spf='fail', dkim='fail', dmarc='fail', kw_score=14, url_score=35, att_score=15),
        ]

        now = timezone.now()
        for i, s in enumerate(samples):
            received = now - timedelta(hours=i * 3, minutes=random.randint(0, 59))
            email, created = Email.objects.get_or_create(
                message_id=s['message_id'],
                defaults=dict(
                    from_address=s['from_address'],
                    from_display_name=s['from_display_name'],
                    subject=s['subject'],
                    body_text=f"This is a demo email body for {s['message_id']}.\n\nLorem ipsum dolor sit amet.",
                    verdict=s['verdict'],
                    score=s['score'],
                    status=s['status'],
                    confidence=s['confidence'],
                    received_at=received,
                    analyzed_at=received + timedelta(seconds=random.randint(1, 5)),
                    to_addresses=['protected@company.com'],
                    urls_extracted=['https://example.com/track'] if s['url_score'] > 0 else [],
                    headers_raw={
                        'From': f"{s['from_display_name']} <{s['from_address']}>",
                        'To': 'protected@company.com',
                        'Subject': s['subject'],
                        'Date': received.isoformat(),
                        'Message-ID': f"<{s['message_id']}@mail>",
                        'X-Mailer': 'Demo Mailer 1.0',
                        'Received': f"from mail.{s['from_address'].split('@')[1]} (unknown [192.168.1.{random.randint(1, 254)}])",
                    },
                    received_chain=[
                        f"from mail.{s['from_address'].split('@')[1]} by mx.company.com",
                    ],
                ),
            )

            if created:
                preprocess = max(0, s['score'] - s['kw_score'] - s['url_score'] - s['att_score'])
                AnalysisResult.objects.get_or_create(
                    email=email,
                    defaults=dict(
                        preprocess_score=preprocess,
                        spf_result=s['spf'],
                        dkim_result=s['dkim'],
                        dmarc_result=s['dmarc'],
                        is_reply_to_mismatch=s['score'] > 40,
                        is_display_spoof=s['score'] > 60,
                        keyword_score=s['kw_score'],
                        keywords_matched=['verify your account', 'urgent action required'] if s['kw_score'] > 5 else [],
                        url_score=s['url_score'],
                        url_findings=[{'url': 'https://phishing-demo.xyz/login', 'score': s['url_score'], 'source': 'URLhaus'}] if s['url_score'] > 0 else [],
                        attachment_score=s['att_score'],
                        attachment_findings=[{'filename': 'invoice.exe', 'match': 'dangerous_extension'}] if s['att_score'] > 0 else [],
                        chain_score=0,
                        chain_findings={},
                        total_score=s['score'],
                        pipeline_duration_ms=random.randint(800, 2500),
                    ),
                )

                # Quarantine for non-clean
                if s['status'] in ('QUARANTINED', 'BLOCKED'):
                    QuarantineEntry.objects.get_or_create(email=email)

                # Attachments for malicious
                if s['verdict'] == 'MALICIOUS':
                    EmailAttachment.objects.get_or_create(
                        email=email,
                        filename='invoice.pdf.exe',
                        defaults=dict(
                            content_type='application/x-msdownload',
                            size_bytes=random.randint(50000, 200000),
                            sha256_hash=f'{random.randint(0, 9)}' * 64,
                            md5_hash=f'{random.randint(0, 9)}' * 32,
                            file_magic='PE32 executable (GUI) Intel 80386',
                            is_dangerous_ext=True,
                            is_double_ext=True,
                            yara_matches=['PE_executable_in_email', 'Double_extension_exe'],
                            ti_match='MALWAREBAZAAR',
                        ),
                    )

                # IOCs for suspicious/malicious
                if s['verdict'] in ('SUSPICIOUS', 'MALICIOUS'):
                    ExtractedIOC.objects.get_or_create(
                        email=email,
                        ioc_type='URL',
                        value='https://phishing-demo.xyz/login',
                        defaults={'severity': 'HIGH', 'source_checker': 'url_checker'},
                    )

        self.stdout.write(self.style.SUCCESS(
            f'Demo data seeded: {Email.objects.count()} emails, '
            f'{QuarantineEntry.objects.count()} quarantine entries, '
            f'{MaliciousHash.objects.count()} TI hashes, '
            f'{MaliciousDomain.objects.count()} TI domains'
        ))
