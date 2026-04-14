from django.conf import settings
from django.db import models


class Email(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('ANALYZING', 'Analyzing'),
        ('DELIVERED', 'Delivered'),
        ('QUARANTINED', 'Quarantined'),
        ('BLOCKED', 'Blocked'),
    ]
    VERDICT_CHOICES = [
        ('CLEAN', 'Clean'),
        ('SUSPICIOUS', 'Suspicious'),
        ('MALICIOUS', 'Malicious'),
    ]
    CONFIDENCE_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
    ]

    message_id = models.CharField(max_length=255, unique=True, db_index=True)
    gmail_id = models.CharField(max_length=100, null=True, blank=True, unique=True, db_index=True)
    from_address = models.EmailField(db_index=True)
    from_display_name = models.CharField(max_length=255, blank=True)
    to_addresses = models.JSONField(default=list)
    cc_addresses = models.JSONField(null=True, blank=True)
    reply_to = models.EmailField(null=True, blank=True)
    subject = models.CharField(max_length=500)
    body_text = models.TextField(blank=True)
    body_html = models.TextField(null=True, blank=True)
    headers_raw = models.JSONField(default=dict)
    received_chain = models.JSONField(default=list)
    urls_extracted = models.JSONField(default=list)
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='PENDING', db_index=True
    )
    verdict = models.CharField(
        max_length=15, choices=VERDICT_CHOICES, null=True, blank=True, db_index=True
    )
    score = models.IntegerField(null=True, blank=True)
    confidence = models.CharField(
        max_length=10, choices=CONFIDENCE_CHOICES, null=True, blank=True
    )
    analyzed_at = models.DateTimeField(null=True, blank=True)
    received_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-received_at']

    def __str__(self):
        return f"{self.subject} from {self.from_address}"


class EmailAttachment(models.Model):
    email = models.ForeignKey(
        Email, on_delete=models.CASCADE, related_name='attachments'
    )
    filename = models.CharField(max_length=255)
    content_type = models.CharField(max_length=100)
    size_bytes = models.IntegerField()
    sha256_hash = models.CharField(max_length=64, db_index=True)
    md5_hash = models.CharField(max_length=32)
    file_magic = models.CharField(max_length=100, null=True, blank=True)
    is_dangerous_ext = models.BooleanField(default=False)
    is_double_ext = models.BooleanField(default=False)
    is_mime_mismatch = models.BooleanField(default=False)
    yara_matches = models.JSONField(null=True, blank=True)
    ti_match = models.CharField(max_length=50, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.filename} ({self.sha256_hash[:8]})"


class AnalysisResult(models.Model):
    SPF_CHOICES = [
        ('pass', 'Pass'),
        ('fail', 'Fail'),
        ('softfail', 'Softfail'),
        ('none', 'None'),
    ]
    DKIM_CHOICES = [
        ('pass', 'Pass'),
        ('fail', 'Fail'),
        ('none', 'None'),
    ]
    DMARC_CHOICES = [
        ('pass', 'Pass'),
        ('fail', 'Fail'),
        ('none', 'None'),
    ]

    email = models.OneToOneField(
        Email, on_delete=models.CASCADE, related_name='analysis'
    )
    preprocess_score = models.IntegerField(default=0)
    spf_result = models.CharField(
        max_length=20, choices=SPF_CHOICES, default='none'
    )
    dkim_result = models.CharField(
        max_length=20, choices=DKIM_CHOICES, default='none'
    )
    dmarc_result = models.CharField(
        max_length=20, choices=DMARC_CHOICES, default='none'
    )
    is_reply_to_mismatch = models.BooleanField(default=False)
    is_display_spoof = models.BooleanField(default=False)
    keyword_score = models.IntegerField(default=0)
    keywords_matched = models.JSONField(default=list)
    url_score = models.IntegerField(default=0)
    url_findings = models.JSONField(default=list)
    attachment_score = models.IntegerField(default=0)
    attachment_findings = models.JSONField(default=list)
    chain_score = models.IntegerField(default=0)
    chain_findings = models.JSONField(default=dict)
    total_score = models.IntegerField(default=0)
    pipeline_duration_ms = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Analysis for {self.email_id} -- score: {self.total_score}"


class QuarantineEntry(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('RELEASED', 'Released'),
        ('DELETED', 'Deleted'),
        ('BLOCKED', 'Blocked'),
    ]

    email = models.OneToOneField(
        Email, on_delete=models.CASCADE, related_name='quarantine'
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='PENDING', db_index=True
    )
    action = models.CharField(max_length=20, null=True, blank=True)
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Quarantine: {self.email.subject} [{self.status}]"


class ExtractedIOC(models.Model):
    IOC_TYPE_CHOICES = [
        ('HASH', 'Hash'),
        ('URL', 'URL'),
        ('IP', 'IP'),
        ('DOMAIN', 'Domain'),
    ]
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]

    email = models.ForeignKey(
        Email, on_delete=models.CASCADE, related_name='iocs'
    )
    ioc_type = models.CharField(
        max_length=20, choices=IOC_TYPE_CHOICES, db_index=True
    )
    value = models.CharField(max_length=500, db_index=True)
    severity = models.CharField(
        max_length=10, choices=SEVERITY_CHOICES, default='HIGH'
    )
    source_checker = models.CharField(max_length=50, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ioc_type}: {self.value[:50]}"


class SystemConfig(models.Model):
    """Singleton configuration for system integration keys and thresholds."""

    # API Keys (encrypted with Fernet using Django SECRET_KEY)
    _virustotal_api_key = models.TextField(blank=True, default='', db_column='virustotal_api_key')
    _abuseipdb_api_key = models.TextField(blank=True, default='', db_column='abuseipdb_api_key')

    # Gmail OAuth status
    gmail_credentials_uploaded = models.BooleanField(default=False)
    gmail_connection_status = models.CharField(
        max_length=20,
        choices=[('DISCONNECTED', 'Disconnected'), ('CONNECTED', 'Connected'), ('EXPIRED', 'Expired')],
        default='DISCONNECTED',
    )
    gmail_connected_email = models.EmailField(blank=True)

    # Detection thresholds
    clean_threshold = models.IntegerField(default=25)
    malicious_threshold = models.IntegerField(default=70)

    # Fetch settings
    fetch_interval_seconds = models.IntegerField(default=10)
    ti_sync_enabled = models.BooleanField(default=True)

    # Audit
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )

    class Meta:
        verbose_name = 'System Configuration'
        verbose_name_plural = 'System Configuration'

    def __str__(self):
        return 'System Configuration'

    @classmethod
    def get_solo(cls):
        """Return the single SystemConfig instance, creating it if needed."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def _get_fernet(self):
        """Create Fernet cipher from Django SECRET_KEY."""
        import base64
        import hashlib
        from cryptography.fernet import Fernet
        from django.conf import settings as django_settings
        key = hashlib.sha256(django_settings.SECRET_KEY.encode()).digest()
        return Fernet(base64.urlsafe_b64encode(key))

    def set_api_key(self, field_name, value):
        """Encrypt and store an API key."""
        if not value:
            setattr(self, field_name, '')
            return
        f = self._get_fernet()
        encrypted = f.encrypt(value.encode()).decode()
        setattr(self, field_name, encrypted)

    def get_api_key(self, field_name):
        """Decrypt and return an API key."""
        encrypted = getattr(self, field_name)
        if not encrypted:
            return ''
        try:
            f = self._get_fernet()
            return f.decrypt(encrypted.encode()).decode()
        except Exception:
            return ''

    @property
    def virustotal_api_key(self):
        return self.get_api_key('_virustotal_api_key')

    @virustotal_api_key.setter
    def virustotal_api_key(self, value):
        self.set_api_key('_virustotal_api_key', value)

    @property
    def abuseipdb_api_key(self):
        return self.get_api_key('_abuseipdb_api_key')

    @abuseipdb_api_key.setter
    def abuseipdb_api_key(self, value):
        self.set_api_key('_abuseipdb_api_key', value)

    def mask_key(self, key_value):
        """Return masked version of an API key for display."""
        if not key_value:
            return ''
        if len(key_value) <= 8:
            return '****'
        return key_value[:4] + '****' + key_value[-4:]
