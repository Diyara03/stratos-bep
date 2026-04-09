from django.conf import settings
from django.db import models


class MaliciousHash(models.Model):
    SOURCE_CHOICES = [
        ('MALWAREBAZAAR', 'MalwareBazaar'),
        ('VIRUSTOTAL', 'VirusTotal'),
        ('MANUAL', 'Manual'),
    ]
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
    ]

    sha256_hash = models.CharField(max_length=64, unique=True, db_index=True)
    md5_hash = models.CharField(max_length=32, blank=True)
    malware_family = models.CharField(max_length=100, blank=True)
    source = models.CharField(
        max_length=30, choices=SOURCE_CHOICES, default='MALWAREBAZAAR'
    )
    severity = models.CharField(
        max_length=10, choices=SEVERITY_CHOICES, default='HIGH'
    )
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sha256_hash[:16]}... ({self.malware_family})"


class MaliciousDomain(models.Model):
    SOURCE_CHOICES = [
        ('URLHAUS', 'URLhaus'),
        ('VIRUSTOTAL', 'VirusTotal'),
        ('ABUSEIPDB', 'AbuseIPDB'),
        ('MANUAL', 'Manual'),
    ]

    domain = models.CharField(max_length=255, unique=True, db_index=True)
    category = models.CharField(max_length=50, blank=True)
    source = models.CharField(
        max_length=30, choices=SOURCE_CHOICES, default='URLHAUS'
    )
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain


class MaliciousIP(models.Model):
    SOURCE_CHOICES = [
        ('ABUSEIPDB', 'AbuseIPDB'),
        ('VIRUSTOTAL', 'VirusTotal'),
        ('MANUAL', 'Manual'),
    ]

    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    category = models.CharField(max_length=50, blank=True)
    source = models.CharField(
        max_length=30, choices=SOURCE_CHOICES, default='ABUSEIPDB'
    )
    abuse_score = models.IntegerField(default=0)
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address


class YaraRule(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
    ]

    name = models.CharField(max_length=100, unique=True)
    rule_content = models.TextField()
    severity = models.CharField(
        max_length=10, choices=SEVERITY_CHOICES, default='HIGH'
    )
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({'active' if self.is_active else 'inactive'})"


class WhitelistEntry(models.Model):
    ENTRY_TYPE_CHOICES = [
        ('EMAIL', 'Email'),
        ('DOMAIN', 'Domain'),
        ('IP', 'IP'),
    ]

    entry_type = models.CharField(max_length=10, choices=ENTRY_TYPE_CHOICES)
    value = models.CharField(max_length=255, db_index=True)
    reason = models.TextField(blank=True)
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('entry_type', 'value')]

    def __str__(self):
        return f"Whitelist {self.entry_type}: {self.value}"


class BlacklistEntry(models.Model):
    ENTRY_TYPE_CHOICES = [
        ('EMAIL', 'Email'),
        ('DOMAIN', 'Domain'),
        ('IP', 'IP'),
    ]

    entry_type = models.CharField(max_length=10, choices=ENTRY_TYPE_CHOICES)
    value = models.CharField(max_length=255, db_index=True)
    reason = models.TextField(blank=True)
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
    )
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('entry_type', 'value')]

    def __str__(self):
        return f"Blacklist {self.entry_type}: {self.value}"
