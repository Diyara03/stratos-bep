"""
Management command to sync threat intelligence feeds.
Imports MaliciousHash records from MalwareBazaar and
MaliciousDomain records from URLhaus.
"""
import csv
import io
import re
import urllib.parse

import requests
from django.core.management.base import BaseCommand

from threat_intel.models import MaliciousDomain, MaliciousHash


class Command(BaseCommand):
    help = 'Sync threat intelligence feeds from MalwareBazaar and URLhaus'

    def add_arguments(self, parser):
        parser.add_argument(
            '--feed',
            type=str,
            choices=['malwarebazaar', 'urlhaus', 'all'],
            default='all',
            help='Which feed to sync (default: all)',
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=5000,
            help='Maximum records to import per feed (default: 5000)',
        )

    def handle(self, *args, **options):
        feed = options['feed']
        limit = options['limit']

        if feed in ('malwarebazaar', 'all'):
            self._sync_malwarebazaar(limit)

        if feed in ('urlhaus', 'all'):
            self._sync_urlhaus(limit)

    def _sync_malwarebazaar(self, limit: int) -> None:
        """Sync hashes from MalwareBazaar recent CSV export."""
        self.stdout.write('Syncing MalwareBazaar...')

        try:
            response = requests.get(
                'https://bazaar.abuse.ch/export/csv/recent/',
                timeout=30,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            self.stderr.write(f'MalwareBazaar fetch failed: {e}')
            return

        # Parse CSV, skipping comment lines starting with '#'
        lines = response.text.splitlines()
        data_lines = [line for line in lines if not line.startswith('#')]

        if not data_lines:
            self.stdout.write('MalwareBazaar: no data lines found')
            return

        reader = csv.reader(io.StringIO('\n'.join(data_lines)))

        # Find header row and column indices
        header = next(reader, None)
        if not header:
            self.stdout.write('MalwareBazaar: no header row found')
            return

        # Strip whitespace from headers
        header = [h.strip().strip('"') for h in header]

        try:
            sha256_idx = header.index('sha256_hash')
            md5_idx = header.index('md5_hash')
            signature_idx = header.index('signature')
        except ValueError as e:
            self.stderr.write(f'MalwareBazaar: missing expected column: {e}')
            return

        sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')
        new_count = 0
        updated_count = 0
        skipped = 0
        upserted = 0

        for row in reader:
            if upserted >= limit:
                break

            try:
                sha256 = row[sha256_idx].strip().strip('"')
                md5 = row[md5_idx].strip().strip('"')
                signature = row[signature_idx].strip().strip('"')
            except IndexError:
                skipped += 1
                continue

            if not sha256_pattern.match(sha256):
                skipped += 1
                continue

            _obj, created = MaliciousHash.objects.update_or_create(
                sha256_hash=sha256,
                defaults={
                    'md5_hash': md5,
                    'malware_family': signature,
                    'source': 'MALWAREBAZAAR',
                },
            )
            if created:
                new_count += 1
            else:
                updated_count += 1
            upserted += 1

        self.stdout.write(
            f'MalwareBazaar: {new_count} new, {updated_count} updated, {skipped} skipped'
        )

    def _sync_urlhaus(self, limit: int) -> None:
        """Sync domains from URLhaus recent CSV export."""
        self.stdout.write('Syncing URLhaus...')

        try:
            response = requests.get(
                'https://urlhaus.abuse.ch/downloads/csv_recent/',
                timeout=30,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            self.stderr.write(f'URLhaus fetch failed: {e}')
            return

        # Parse CSV, skipping comment lines starting with '#'
        lines = response.text.splitlines()
        data_lines = [line for line in lines if not line.startswith('#')]

        if not data_lines:
            self.stdout.write('URLhaus: no data lines found')
            return

        reader = csv.reader(io.StringIO('\n'.join(data_lines)))

        # Find header row and column indices
        header = next(reader, None)
        if not header:
            self.stdout.write('URLhaus: no header row found')
            return

        # Strip whitespace from headers
        header = [h.strip().strip('"') for h in header]

        try:
            url_idx = header.index('url')
            status_idx = header.index('url_status')
        except ValueError as e:
            self.stderr.write(f'URLhaus: missing expected column: {e}')
            return

        # Try to find a threat column for category
        threat_idx = None
        for candidate in ('threat', 'tags', 'threat_type'):
            if candidate in header:
                threat_idx = header.index(candidate)
                break

        new_count = 0
        updated_count = 0
        skipped = 0
        upserted = 0

        for row in reader:
            if upserted >= limit:
                break

            try:
                url = row[url_idx].strip().strip('"')
                url_status = row[status_idx].strip().strip('"')
            except IndexError:
                skipped += 1
                continue

            if url_status != 'online':
                skipped += 1
                continue

            hostname = urllib.parse.urlparse(url).hostname
            if not hostname:
                skipped += 1
                continue

            category = 'threat'
            if threat_idx is not None:
                try:
                    val = row[threat_idx].strip().strip('"')
                    if val:
                        category = val
                except IndexError:
                    pass

            _obj, created = MaliciousDomain.objects.update_or_create(
                domain=hostname,
                defaults={
                    'category': category,
                    'source': 'URLHAUS',
                },
            )
            if created:
                new_count += 1
            else:
                updated_count += 1
            upserted += 1

        self.stdout.write(
            f'URLhaus: {new_count} new, {updated_count} updated, {skipped} skipped'
        )
