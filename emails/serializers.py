"""
DRF serializers for the Stratos BEP email API.
"""
from rest_framework import serializers

from emails.models import AnalysisResult, Email, EmailAttachment, QuarantineEntry


class EmailListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Email
        fields = [
            'id', 'message_id', 'from_address', 'from_display_name',
            'subject', 'verdict', 'score', 'confidence', 'status',
            'received_at',
        ]


class EmailAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailAttachment
        fields = [
            'id', 'filename', 'content_type', 'size_bytes',
            'sha256_hash', 'md5_hash', 'file_magic',
            'is_dangerous_ext', 'is_double_ext', 'is_mime_mismatch',
            'yara_matches', 'ti_match', 'created_at',
        ]


class AnalysisResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalysisResult
        fields = [
            'id', 'preprocess_score', 'spf_result', 'dkim_result',
            'dmarc_result', 'is_reply_to_mismatch', 'is_display_spoof',
            'keyword_score', 'keywords_matched', 'url_score', 'url_findings',
            'attachment_score', 'attachment_findings', 'chain_score',
            'chain_findings', 'total_score', 'pipeline_duration_ms',
            'created_at',
        ]


class EmailDetailSerializer(EmailListSerializer):
    analysis = AnalysisResultSerializer(read_only=True)
    attachments = EmailAttachmentSerializer(read_only=True, many=True)

    class Meta(EmailListSerializer.Meta):
        fields = EmailListSerializer.Meta.fields + [
            'to_addresses', 'reply_to', 'body_text', 'urls_extracted',
            'analyzed_at', 'created_at', 'analysis', 'attachments',
        ]


class QuarantineEntrySerializer(serializers.ModelSerializer):
    email = EmailListSerializer(read_only=True)

    class Meta:
        model = QuarantineEntry
        fields = [
            'id', 'status', 'action', 'reviewed_at', 'notes',
            'created_at', 'email',
        ]


class QuarantineActionSerializer(serializers.Serializer):
    action = serializers.ChoiceField(
        choices=['release', 'block', 'delete'],
        error_messages={
            'invalid_choice': 'Invalid action. Choose from: release, block, delete.',
        },
    )
    notes = serializers.CharField(required=False, default='')


class DashboardStatsSerializer(serializers.Serializer):
    total_emails = serializers.IntegerField()
    clean_count = serializers.IntegerField()
    suspicious_count = serializers.IntegerField()
    malicious_count = serializers.IntegerField()
    pending_count = serializers.IntegerField()
    quarantine_pending = serializers.IntegerField()
    ti_hashes = serializers.IntegerField()
    ti_domains = serializers.IntegerField()
    last_sync = serializers.DateTimeField(allow_null=True)
