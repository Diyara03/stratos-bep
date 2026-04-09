"""Set up complete demo scenario for viva presentation."""
import random
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils import timezone

from emails.models import (
    AnalysisResult, Email, EmailAttachment, ExtractedIOC, QuarantineEntry,
)
from threat_intel.models import (
    BlacklistEntry, MaliciousDomain, MaliciousHash, MaliciousIP,
    WhitelistEntry, YaraRule,
)

User = get_user_model()


class Command(BaseCommand):
    help = 'Set up complete demo scenario for viva presentation'

    def add_arguments(self, parser):
        parser.add_argument('--flush', action='store_true', help='Clear existing demo data first')

    def handle(self, *args, **options):
        if options['flush']:
            Email.objects.filter(message_id__startswith='demo-').delete()
            self.stdout.write('Flushed existing demo emails.')

        # ── Users ──
        admin, created = User.objects.get_or_create(
            username='admin',
            defaults={'email': 'admin@stratos.local', 'role': 'ADMIN', 'is_staff': True, 'is_superuser': True},
        )
        if created:
            admin.set_password('admin123')
            admin.save()

        analyst, created = User.objects.get_or_create(
            username='analyst',
            defaults={'email': 'analyst@stratos.local', 'role': 'ANALYST'},
        )
        if created:
            analyst.set_password('analyst123')
            analyst.save()

        viewer, created = User.objects.get_or_create(
            username='viewer',
            defaults={'email': 'viewer@stratos.local', 'role': 'VIEWER'},
        )
        if created:
            viewer.set_password('viewer123')
            viewer.save()

        # ── Threat Intel ──
        hashes = [
            ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Emotet.Gen', 'MALWAREBAZAAR', 'CRITICAL'),
            ('a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a', 'AgentTesla', 'MALWAREBAZAAR', 'HIGH'),
            ('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', 'QakBot', 'VIRUSTOTAL', 'CRITICAL'),
            ('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592', 'TrickBot', 'MALWAREBAZAAR', 'HIGH'),
            ('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'Dridex', 'VIRUSTOTAL', 'HIGH'),
        ]
        for sha, family, source, severity in hashes:
            MaliciousHash.objects.get_or_create(
                sha256_hash=sha, defaults={'malware_family': family, 'source': source, 'severity': severity}
            )

        domains = [
            ('phishing-login.xyz', 'phishing', 'URLHAUS'),
            ('malware-c2-server.ru', 'c2', 'URLHAUS'),
            ('fake-bank-verify.com', 'phishing', 'URLHAUS'),
            ('secure-update-now.net', 'malware', 'VIRUSTOTAL'),
            ('ministry-of-justice.uz.phishing-demo.xyz', 'phishing', 'URLHAUS'),
        ]
        for domain, cat, source in domains:
            MaliciousDomain.objects.get_or_create(
                domain=domain, defaults={'category': cat, 'source': source}
            )

        MaliciousIP.objects.get_or_create(ip_address='185.220.101.42', defaults={'category': 'botnet', 'source': 'ABUSEIPDB', 'abuse_score': 100})
        MaliciousIP.objects.get_or_create(ip_address='45.33.32.156', defaults={'category': 'scanner', 'source': 'ABUSEIPDB', 'abuse_score': 85})

        yara_rules = [
            ('VBA_macro_suspicious', 'rule VBA_macro_suspicious { condition: true }', 'HIGH', 'Detects suspicious VBA macros in documents'),
            ('PE_executable_in_email', 'rule PE_executable_in_email { condition: true }', 'CRITICAL', 'PE executable attached to email'),
            ('JS_obfuscation_pattern', 'rule JS_obfuscation_pattern { condition: true }', 'HIGH', 'Obfuscated JavaScript in attachment'),
        ]
        for name, content, severity, desc in yara_rules:
            YaraRule.objects.get_or_create(name=name, defaults={'rule_content': content, 'severity': severity, 'description': desc})

        WhitelistEntry.objects.get_or_create(entry_type='DOMAIN', value='company.com', defaults={'reason': 'Internal corporate domain', 'added_by': admin})
        WhitelistEntry.objects.get_or_create(entry_type='EMAIL', value='ceo@company.com', defaults={'reason': 'CEO direct address', 'added_by': admin})
        BlacklistEntry.objects.get_or_create(entry_type='DOMAIN', value='phishing-login.xyz', defaults={'reason': 'Known phishing domain', 'added_by': admin})
        BlacklistEntry.objects.get_or_create(entry_type='DOMAIN', value='malware-c2-server.ru', defaults={'reason': 'C2 infrastructure', 'added_by': admin})

        # ── Emails ──
        now = timezone.now()
        samples = [
            # 3 CLEAN
            dict(
                message_id='demo-clean-001', from_address='alice@company.com', from_display_name='Alice Johnson',
                subject='Q4 Budget Report -- Final Version', body_text='Hi team,\n\nPlease find attached the final Q4 budget report. All numbers have been reviewed by the finance department.\n\nBest regards,\nAlice',
                verdict='CLEAN', score=5, status='DELIVERED', confidence='HIGH',
                spf='pass', dkim='pass', dmarc='pass', kw_score=0, url_score=0, att_score=0, chain_score=0, preprocess=5,
                reply_to_mismatch=False, display_spoof=False, keywords=[],
            ),
            dict(
                message_id='demo-clean-002', from_address='bob@partner.org', from_display_name='Bob Williams',
                subject='Meeting agenda for Thursday', body_text='Hi,\n\nHere is the agenda for our meeting on Thursday.\n\n1. Project status update\n2. Budget review\n3. Next steps\n\nRegards,\nBob',
                verdict='CLEAN', score=8, status='DELIVERED', confidence='HIGH',
                spf='pass', dkim='pass', dmarc='pass', kw_score=0, url_score=0, att_score=0, chain_score=0, preprocess=8,
                reply_to_mismatch=False, display_spoof=False, keywords=[],
            ),
            dict(
                message_id='demo-clean-003', from_address='hr@company.com', from_display_name='HR Department',
                subject='Holiday schedule 2026', body_text='Dear all,\n\nPlease find the updated holiday schedule for 2026 attached.\n\nHR Department',
                verdict='CLEAN', score=3, status='DELIVERED', confidence='HIGH',
                spf='pass', dkim='pass', dmarc='pass', kw_score=0, url_score=0, att_score=0, chain_score=0, preprocess=3,
                reply_to_mismatch=False, display_spoof=False, keywords=[],
            ),
            # 4 SUSPICIOUS
            dict(
                message_id='demo-susp-001', from_address='billing@paypa1.com', from_display_name='PayPal Billing',
                subject='Urgent: Verify your account immediately', body_text='Dear Customer,\n\nWe have detected unusual activity on your account. Please verify your account immediately to avoid suspension.\n\nClick here to verify.',
                verdict='SUSPICIOUS', score=48, status='QUARANTINED', confidence='LOW',
                spf='softfail', dkim='fail', dmarc='fail', kw_score=10, url_score=0, att_score=0, chain_score=0, preprocess=38,
                reply_to_mismatch=True, display_spoof=False, keywords=['verify your account', 'unusual activity', 'suspended account', 'click here immediately', 'urgent action required'],
            ),
            dict(
                message_id='demo-susp-002', from_address='security@bank-alert.net', from_display_name='Bank Security',
                subject='Security alert: Unusual activity detected', body_text='URGENT: We detected unauthorized access to your online banking. Reset your password immediately.\n\nClick the link below to secure your account.',
                verdict='SUSPICIOUS', score=55, status='QUARANTINED', confidence='LOW',
                spf='fail', dkim='fail', dmarc='fail', kw_score=12, url_score=0, att_score=0, chain_score=0, preprocess=43,
                reply_to_mismatch=False, display_spoof=True, keywords=['security alert', 'unusual activity', 'unauthorized access', 'reset your password', 'urgent action required', 'click here immediately'],
            ),
            dict(
                message_id='demo-susp-003', from_address='noreply@invoice-portal.xyz', from_display_name='Invoice Portal',
                subject='Invoice attached -- wire transfer required', body_text='Please find attached invoice #INV-2026-0419.\n\nPayment via wire transfer is required within 48 hours.\n\nBank account details are in the attachment.',
                verdict='SUSPICIOUS', score=38, status='QUARANTINED', confidence='LOW',
                spf='softfail', dkim='none', dmarc='none', kw_score=8, url_score=0, att_score=0, chain_score=5, preprocess=25,
                reply_to_mismatch=False, display_spoof=False, keywords=['invoice attached', 'wire transfer', 'bank account details', 'act now'],
            ),
            dict(
                message_id='demo-susp-004', from_address='support@micros0ft-update.com', from_display_name='Microsoft Support',
                subject='Important security update available', body_text='Your system requires an important security update. Click below to download and install.\n\nDo not share this link with anyone.',
                verdict='SUSPICIOUS', score=42, status='QUARANTINED', confidence='LOW',
                spf='fail', dkim='none', dmarc='fail', kw_score=6, url_score=0, att_score=0, chain_score=0, preprocess=36,
                reply_to_mismatch=True, display_spoof=False, keywords=['important security update', 'do not share with anyone', 'act now'],
            ),
            # 3 MALICIOUS
            dict(
                message_id='demo-mal-001', from_address='attacker@ministry-of-justice.uz.phishing-demo.xyz', from_display_name='Ministry of Justice',
                subject='Urgent: Verify your identity -- account suspended', body_text='Dear Citizen,\n\nYour government account has been suspended due to unusual activity. Verify your identity immediately by clicking the link below.\n\nFailure to act now will result in permanent account closure.\n\nMinistry of Justice\nRepublic of Uzbekistan',
                verdict='MALICIOUS', score=88, status='BLOCKED', confidence='MEDIUM',
                spf='fail', dkim='fail', dmarc='fail', kw_score=16, url_score=30, att_score=0, chain_score=0, preprocess=42,
                reply_to_mismatch=True, display_spoof=True, keywords=['verify your identity', 'urgent action required', 'suspended account', 'click here immediately', 'unusual activity', 'your account will be closed', 'act now', 'verify your information'],
            ),
            dict(
                message_id='demo-mal-002', from_address='hr-dept@company-payroll.ru', from_display_name='HR Payroll',
                subject='Confidential: Bitcoin payment request', body_text='CONFIDENTIAL\n\nPlease process the following bitcoin payment urgently. This is a direct request from the CEO.\n\nAmount: 2.5 BTC\nWallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n\nDo not share with anyone. Reply urgently.',
                verdict='MALICIOUS', score=92, status='BLOCKED', confidence='HIGH',
                spf='fail', dkim='fail', dmarc='fail', kw_score=14, url_score=0, att_score=35, chain_score=0, preprocess=43,
                reply_to_mismatch=True, display_spoof=True, keywords=['bitcoin payment', 'confidential request', 'do not share with anyone', 'reply urgently', 'urgent action required', 'gift card', 'act now'],
            ),
            dict(
                message_id='demo-mal-003', from_address='support@micros0ft-security.com', from_display_name='Microsoft Security',
                subject='Critical security update -- click here immediately', body_text='Your Windows license has expired. Click here immediately to reactivate.\n\nIf you do not act now, your computer will be locked.\n\nMicrosoft Security Team',
                verdict='MALICIOUS', score=78, status='BLOCKED', confidence='MEDIUM',
                spf='fail', dkim='fail', dmarc='fail', kw_score=10, url_score=25, att_score=15, chain_score=0, preprocess=28,
                reply_to_mismatch=False, display_spoof=True, keywords=['click here immediately', 'act now', 'important security update', 'limited time offer', 'your account will be closed'],
            ),
        ]

        for i, s in enumerate(samples):
            received = now - timedelta(hours=i * 2, minutes=random.randint(0, 30))
            email, created = Email.objects.get_or_create(
                message_id=s['message_id'],
                defaults=dict(
                    from_address=s['from_address'],
                    from_display_name=s['from_display_name'],
                    subject=s['subject'],
                    body_text=s['body_text'],
                    verdict=s['verdict'],
                    score=s['score'],
                    status=s['status'],
                    confidence=s['confidence'],
                    received_at=received,
                    analyzed_at=received + timedelta(seconds=random.randint(2, 8)),
                    to_addresses=['protected@company.com'],
                    urls_extracted=['https://phishing-login.xyz/verify'] if s['url_score'] > 0 else [],
                    headers_raw={
                        'From': f"{s['from_display_name']} <{s['from_address']}>",
                        'To': 'protected@company.com',
                        'Subject': s['subject'],
                        'Date': received.isoformat(),
                        'Message-ID': f"<{s['message_id']}@mail>",
                        'X-Mailer': 'Demo Mailer 1.0',
                        'Authentication-Results': f"mx.company.com; spf={s['spf']}; dkim={s['dkim']}; dmarc={s['dmarc']}",
                        'Received': f"from mail.{s['from_address'].split('@')[1]} (unknown [{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}])",
                    },
                    received_chain=[f"from mail.{s['from_address'].split('@')[1]} by mx.company.com"],
                    reply_to=f"reply-{s['from_address']}" if s.get('reply_to_mismatch') else '',
                ),
            )

            if created:
                AnalysisResult.objects.get_or_create(
                    email=email,
                    defaults=dict(
                        preprocess_score=s['preprocess'],
                        spf_result=s['spf'],
                        dkim_result=s['dkim'],
                        dmarc_result=s['dmarc'],
                        is_reply_to_mismatch=s.get('reply_to_mismatch', False),
                        is_display_spoof=s.get('display_spoof', False),
                        keyword_score=s['kw_score'],
                        keywords_matched=s.get('keywords', []),
                        url_score=s['url_score'],
                        url_findings=[{'url': 'https://phishing-login.xyz/verify', 'score': s['url_score'], 'source': 'URLhaus'}] if s['url_score'] > 0 else [],
                        attachment_score=s['att_score'],
                        attachment_findings=[{'filename': 'invoice.pdf.exe', 'match': 'dangerous_extension'}] if s['att_score'] > 0 else [],
                        chain_score=s.get('chain_score', 0),
                        chain_findings={'excessive_hops': True} if s.get('chain_score', 0) > 0 else {},
                        total_score=s['score'],
                        pipeline_duration_ms=random.randint(1200, 3500),
                    ),
                )

                if s['status'] in ('QUARANTINED', 'BLOCKED'):
                    QuarantineEntry.objects.get_or_create(email=email)

                if s['verdict'] == 'MALICIOUS':
                    EmailAttachment.objects.get_or_create(
                        email=email, filename='invoice.pdf.exe',
                        defaults=dict(
                            content_type='application/x-msdownload', size_bytes=random.randint(50000, 250000),
                            sha256_hash='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                            md5_hash='d41d8cd98f00b204e9800998ecf8427e',
                            file_magic='PE32 executable (GUI) Intel 80386',
                            is_dangerous_ext=True, is_double_ext=True,
                            yara_matches=['PE_executable_in_email', 'VBA_macro_suspicious'],
                            ti_match='MALWAREBAZAAR',
                        ),
                    )

                if s['verdict'] in ('SUSPICIOUS', 'MALICIOUS'):
                    if s['url_score'] > 0:
                        ExtractedIOC.objects.get_or_create(
                            email=email, ioc_type='URL', value='https://phishing-login.xyz/verify',
                            defaults={'severity': 'HIGH', 'source_checker': 'url_checker'},
                        )
                    ExtractedIOC.objects.get_or_create(
                        email=email, ioc_type='DOMAIN', value=s['from_address'].split('@')[1],
                        defaults={'severity': 'MEDIUM', 'source_checker': 'preprocessor'},
                    )

        # Summary
        email_count = Email.objects.filter(message_id__startswith='demo-').count()
        quarantine_count = QuarantineEntry.objects.filter(email__message_id__startswith='demo-').count()
        self.stdout.write(self.style.SUCCESS('Demo setup complete'))
        self.stdout.write(f'Users: admin/admin123, analyst/analyst123, viewer/viewer123')
        self.stdout.write(f'Emails: {email_count} (3 clean, 4 suspicious, 3 malicious)')
        self.stdout.write(f'Quarantine: {quarantine_count} pending review')
        self.stdout.write(f'TI: {MaliciousHash.objects.count()} hashes, {MaliciousDomain.objects.count()} domains, {YaraRule.objects.count()} YARA rules')
