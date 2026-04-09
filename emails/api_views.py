"""
DRF API views for the Stratos BEP email API.
"""
from django.db.models import Max
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView

from emails.models import AnalysisResult, Email, QuarantineEntry
from emails.permissions import IsAnalystOrAbove
from emails.serializers import (
    DashboardStatsSerializer,
    EmailDetailSerializer,
    EmailListSerializer,
    QuarantineActionSerializer,
    QuarantineEntrySerializer,
)
from threat_intel.models import MaliciousDomain, MaliciousHash


class EmailListView(generics.ListAPIView):
    """GET /api/emails/ -- paginated, filterable email list."""

    serializer_class = EmailListSerializer

    def get_queryset(self):
        qs = Email.objects.all().order_by('-received_at')
        params = self.request.query_params

        verdict = params.get('verdict')
        if verdict:
            qs = qs.filter(verdict=verdict)

        email_status = params.get('status')
        if email_status:
            qs = qs.filter(status=email_status)

        from_address = params.get('from_address')
        if from_address:
            qs = qs.filter(from_address__icontains=from_address)

        date_from = params.get('date_from')
        if date_from:
            qs = qs.filter(received_at__gte=date_from)

        date_to = params.get('date_to')
        if date_to:
            qs = qs.filter(received_at__lte=date_to)

        return qs


class EmailDetailView(generics.RetrieveAPIView):
    """GET /api/emails/<pk>/ -- full email detail with nested analysis and attachments."""

    serializer_class = EmailDetailSerializer
    queryset = Email.objects.select_related('analysis').prefetch_related('attachments')


class QuarantineListView(generics.ListAPIView):
    """GET /api/quarantine/ -- list quarantined/blocked entries."""

    serializer_class = QuarantineEntrySerializer

    def get_queryset(self):
        qs = QuarantineEntry.objects.select_related('email').filter(
            email__status__in=['QUARANTINED', 'BLOCKED'],
        ).order_by('-created_at')

        quarantine_status = self.request.query_params.get('status')
        if quarantine_status:
            qs = qs.filter(status=quarantine_status)

        return qs


class QuarantineActionView(generics.GenericAPIView):
    """POST /api/quarantine/<pk>/action/ -- release, block, or delete a quarantine entry."""

    serializer_class = QuarantineActionSerializer
    permission_classes = [IsAnalystOrAbove]
    queryset = QuarantineEntry.objects.select_related('email')

    def post(self, request, pk):
        entry = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        action = serializer.validated_data['action']
        notes = serializer.validated_data.get('notes', '')

        if action == 'release':
            entry.status = 'RELEASED'
            entry.notes = notes
            entry.reviewed_at = timezone.now()
            entry.reviewer = request.user
            entry.save()

            entry.email.status = 'DELIVERED'
            entry.email.save(update_fields=['status', 'updated_at'])

            return Response(
                QuarantineEntrySerializer(entry).data,
                status=status.HTTP_200_OK,
            )

        if action == 'block':
            entry.status = 'BLOCKED'
            entry.notes = notes
            entry.reviewed_at = timezone.now()
            entry.reviewer = request.user
            entry.save()

            entry.email.status = 'BLOCKED'
            entry.email.save(update_fields=['status', 'updated_at'])

            return Response(
                QuarantineEntrySerializer(entry).data,
                status=status.HTTP_200_OK,
            )

        if action == 'delete':
            # Permanent delete -- cascades to QuarantineEntry, AnalysisResult, etc.
            entry.email.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        return Response(
            {'action': ['Invalid action. Choose from: release, block, delete.']},
            status=status.HTTP_400_BAD_REQUEST,
        )


class DashboardStatsView(APIView):
    """GET /api/dashboard/stats/ -- aggregate dashboard statistics."""

    def get(self, request):
        hash_max = MaliciousHash.objects.aggregate(max_at=Max('added_at'))['max_at']
        domain_max = MaliciousDomain.objects.aggregate(max_at=Max('added_at'))['max_at']

        # Compute last_sync as the max of both
        last_sync = None
        if hash_max and domain_max:
            last_sync = max(hash_max, domain_max)
        elif hash_max:
            last_sync = hash_max
        elif domain_max:
            last_sync = domain_max

        data = {
            'total_emails': Email.objects.count(),
            'clean_count': Email.objects.filter(verdict='CLEAN').count(),
            'suspicious_count': Email.objects.filter(verdict='SUSPICIOUS').count(),
            'malicious_count': Email.objects.filter(verdict='MALICIOUS').count(),
            'pending_count': Email.objects.filter(verdict__isnull=True).count(),
            'quarantine_pending': QuarantineEntry.objects.filter(status='PENDING').count(),
            'ti_hashes': MaliciousHash.objects.count(),
            'ti_domains': MaliciousDomain.objects.count(),
            'last_sync': last_sync,
        }

        serializer = DashboardStatsSerializer(data)
        return Response(serializer.data)
