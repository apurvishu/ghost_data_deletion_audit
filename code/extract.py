"""Evidence extraction. No predictions, case labels, or sample answers live here."""
from __future__ import annotations
import base64
import csv
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone

_local_deps = Path(__file__).resolve().parents[1] / '.deps'
if _local_deps.exists(): sys.path.insert(0, str(_local_deps))


def read_csv(path):
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


RESOURCE = re.compile(r'\b(?:account|analytics|audit_record|backup|cache|data_flow|email_delivery|export|legal_hold|marketing|object|search|secondary|support|telemetry|tombstone)_\d+\b')
IDENT = re.compile(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}|\buser_\d+\b|\b[a-fA-F0-9]{64}\b')
KV = re.compile(r'(\w+)=(?:"([^"\n]*)"|([^\s|]+))')


def instant(value):
    """Compare ISO timestamps as instants, including offsets and fractional seconds."""
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Evidence timestamps must include a timezone')
    return result.astimezone(timezone.utc)


def kv(text):
    return {m[0]: m[1] if m[1] != '' else m[2] for m in KV.findall(text.replace('\\"', '"'))}


def pdf_text(path):
    """Extract literal text from supplied text PDFs; use pypdf when installed."""
    try:
        from pypdf import PdfReader
        return '\n'.join(p.extract_text() or '' for p in PdfReader(path).pages)
    except ImportError:
        out = []
        for stream in re.findall(rb'stream\r?\n(.*?)endstream', Path(path).read_bytes(), re.S):
            try:
                if stream.rstrip().endswith(b'~>'):
                    stream = base64.a85decode(stream.strip()[:-2], adobe=False)
                stream = zlib.decompress(stream)
            except (ValueError, zlib.error):
                continue
            if b'BT' not in stream:
                continue
            for token in re.findall(rb'\(((?:\\.|[^\\)])*)\)\s*Tj', stream):
                token = re.sub(rb'\\([0-7]{1,3})', lambda m: bytes([int(m[1], 8)]), token)
                token = re.sub(rb'\\([()\\])', rb'\1', token)
                out.append(token.decode('latin-1'))
        if not out:
            raise ValueError(f'No PDF text extracted: {path}')
        return '\n'.join(out)


def image_text(path):
    if os.name == 'nt':
        result = subprocess.run(['powershell', '-NoProfile', '-File', str(Path(__file__).with_name('ocr_windows.ps1')), '-ImagePath', str(path.resolve())], capture_output=True, check=True)
        return result.stdout.decode('utf-8-sig')
    result = subprocess.run(['tesseract', str(path), 'stdout'], capture_output=True, check=True)
    return result.stdout.decode('utf-8')


@dataclass
class Observation:
    resource: str
    system: str
    category: str
    at: str
    available: str
    evidence: str
    data: dict
    text: str
    copy: str = ''
    identity_text: str = ''
    link_available: str = ''


PREFIXES = {
    'account': ('account_service', 'USER_PROFILE'),
    'search': ('search_service', 'SEARCH_INDEX_ENTRY'),
    'analytics': ('analytics_platform', 'ANALYTICS_PROFILE'),
    'data_flow': ('integration_service', 'DATA_FLOW'),
    'backup': ('backup_service', 'BACKUP_ARCHIVE'),
    'export': ('export_service', 'USER_EXPORT'),
    'support': ('support_platform', 'SUPPORT_MESSAGE'),
    'audit_record': ('security_service', 'SECURITY_AUDIT_LOG'),
    'tombstone': ('identity_service', 'ACCOUNT_TOMBSTONE'),
    'marketing': ('marketing_platform', 'MARKETING_PROFILE'),
    'email_delivery': ('email_delivery_service', 'EMAIL_DELIVERY_LOG'),
    'legal_hold': ('legal_service', 'LEGAL_HOLD_RECORD'),
    'cache': ('cache_service', 'CACHE_ENTRY'),
    'secondary': ('identity_service', 'SECONDARY_IDENTIFIER'),
    'telemetry': ('telemetry_service', 'PRODUCT_TELEMETRY'),
    'object': ('object_storage', 'SUPPORT_ATTACHMENT'),
}


class Evidence:
    def __init__(self, dataset):
        self.dataset = Path(dataset)
        self.observations = []
        self.scopes = []
        self.copy_scopes = []
        self.complete_account_files = set()
        self.texts = {}
        self.catalog = {}
        for activity in read_csv(self.dataset/'system_activity.csv'):
            if activity['event_type']=='LINK_RESOURCE_IDENTITY':
                self.catalog.setdefault(activity['resource_id'],[]).append(activity)
        self.manifest = read_csv(self.dataset / 'evidence_files.csv')
        for item in self.manifest:
            path = (self.dataset / item['file_path']).resolve()
            if not path.is_relative_to(self.dataset.resolve() / 'evidence'):
                raise ValueError('Evidence path leaves evidence directory')
            self.load(path, item)
        # Catalog aliases connect ordinary business artifacts that omit resource IDs.
        for activity in (a for values in self.catalog.values() for a in values):
            resource = activity['resource_id']
            aliases = re.findall(r'\(([^)]+)\)', activity['details'])
            for item in self.manifest:
                if Path(item['file_path']).suffix not in ('.pdf','.png'):continue
                text = self.texts.get(item['file_id'], '')
                # A shared user reference is not a resource alias in a multi-person
                # finance register. Require an exact resource/file alias or a unique
                # stable reference in a reference-registry artifact.
                stable_refs=set(re.findall(r'\buser_\d+\b',text))
                matched=any(alias in text and (not re.fullmatch(r'user_\d+',alias) or
                    (stable_refs=={alias} and 'reference registry' in text.casefold())) for alias in aliases)
                if matched:
                    category=PREFIXES.get(resource.rsplit('_',1)[0],('',''))[1]
                    data={'document_text':text}
                    if category=='ACCOUNT_TOMBSTONE' and not re.search(r'[\w.+-]+@[\w.-]+',text):
                        data['reference_only']=True
                    self.add(resource,data,item,system=activity['target_system'],category=category,text=text,
                             identity_text=activity['details'],link_available=activity['event_time'])

    def add(self, resource, data, item, at='', system='', category='', copy='', text='',identity_text='',link_available=''):
        if not resource:
            return
        prefix = resource.rsplit('_', 1)[0]
        default_system, default_category = PREFIXES.get(prefix, ('', ''))
        category = category or data.get('record_type') or default_category
        if any(k in data for k in ['attachment_name', 'attachment_text', 'attachment_id']):
            category = 'SUPPORT_ATTACHMENT' if prefix == 'support' else category
        self.observations.append(Observation(resource, system or data.get('system') or default_system, category,
            at or data.get('recorded_at') or data.get('observed_at') or item['captured_at'], item['captured_at'],
            item['file_id'], data, text or json.dumps(data, ensure_ascii=False), copy,identity_text,link_available))

    def load(self, path, item):
        suffix = path.suffix
        if suffix == '.json':
            obj = json.loads(path.read_text(encoding='utf-8'))
            if 'snapshots' in obj:
                for snap in obj['snapshots']:
                    system = snap['data_store']; at = snap['captured_at']
                    self.scopes.append((system, at, item['captured_at'], item['file_id'], {r['resource_id'] for r in snap['records']}))
                    for rec in snap['records']:
                        self.add(rec['resource_id'], rec, item, at, system, copy=snap['collection'])
            elif 'service_exports' in obj:
                for system, groups in obj['service_exports'].items():
                    for group, records in groups.items():
                        for rec in records:
                            self.add(rec['resource_id'], rec, item, system=system, copy=group)
            else:
                for rec in obj.get('records', []):
                    self.add(rec['resource_id'], rec, item, system=rec.get('system', ''), copy=obj.get('collection', ''))
        elif suffix == '.sql':
            conn = sqlite3.connect(':memory:'); conn.row_factory = sqlite3.Row
            sql = path.read_text(encoding='utf-8')
            # No file operations or executable extensions are allowed in evidence SQL.
            if re.search(r'\b(?:ATTACH|DETACH|load_extension|VACUUM)\b', sql, re.I):
                raise ValueError('Unsafe SQL evidence')
            conn.executescript(sql)
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            table_records={table:[dict(r) for r in conn.execute('SELECT * FROM "'+table.replace('"','""')+'"')] for table in tables}
            snapshot_systems={r['origin_system'] for rows in table_records.values() for r in rows if 'origin_system' in r}
            for table in tables:
                records = table_records[table]
                if table == 'snapshot_scope':
                    for r in records:
                        self.scopes.append((r['origin_system'], r['captured_at'], item['captured_at'], item['file_id'], {x['resource_id'] for t in tables if t != table for x in conn.execute('SELECT * FROM "' + t + '"') if 'resource_id' in x.keys()}))
                    continue
                for rec in records:
                    if 'resource_id' not in rec:
                        continue
                    data = json.loads(rec['record_json']) if 'record_json' in rec else rec
                    self.add(rec['resource_id'], data, item, item['captured_at'], rec.get('origin_system', ''), copy=table)
                # Complete account tables support negative lookups by a grounded resource ID.
                if table.startswith('customer_profiles'):
                    self.scopes.append(('account_service',item['captured_at'],item['captured_at'],item['file_id'],{r['resource_id'] for r in records}))
                    self.copy_scopes.append(('account_service',table,item['captured_at'],item['captured_at'],item['file_id'],{r['resource_id'] for r in records}))
                    if table in ('customer_profiles_primary','customer_profiles_failover_replica'):self.complete_account_files.add(item['file_id'])
                elif table.startswith('customer_data_') and ('primary' in table or 'replica' in table):
                    for system in snapshot_systems:
                        present={r['resource_id'] for r in records if r.get('origin_system')==system}
                        self.copy_scopes.append((system,table,item['captured_at'],item['captured_at'],item['file_id'],present))
            conn.close()
        else:
            text = pdf_text(path) if suffix == '.pdf' else image_text(path) if suffix == '.png' else path.read_text(encoding='utf-8')
            if suffix == '.png':
                text = re.sub(r'(account|analytics|audit_record|backup|data_flow|export|marketing|search|support|user)\s*_\s*',r'\1_',text)
                text = re.sub(r'\buser\s+(\d+)\b',r'user_\1',text)
            self.texts[item['file_id']] = text
            if suffix == '.log':
                self.load_log(text, item)
            elif suffix == '.txt':
                for line in text.splitlines():
                    parts = [p.strip() for p in line.lstrip('- ').split('|')]
                    if len(parts) == 6:
                        at, system, resource, category, result, subject = parts
                        self.add(resource, {'result':result,'subject_reference':subject}, item, at, system, category)
            else:
                # Ordinary business documents: preserve text context for interpretation.
                for resource in sorted(set(RESOURCE.findall(text))):
                    category = 'SUPPORT_ATTACHMENT' if suffix=='.pdf' and 'attachment' in text.casefold() and resource.startswith('support_') else ''
                    self.add(resource, {'document_text':text}, item, category=category,text=text)

    def load_log(self, text, item):
        traces = {}
        for line in text.splitlines():
            at = line.split(None,1)[0]
            if '{' in line:
                try: d = json.loads(line[line.index('{'):])
                except ValueError: d = kv(line)
            else: d = kv(line)
            # Parse bracketed and pipe-separated event names before retaining trace
            # context; otherwise a previous event can mask the current readback.
            if not d.get('event'):
                m=re.search(r'\]\s+(\w+)\s*:',line)
                if not m and ' | ' in line:
                    parts=line.split(' | ')
                    if len(parts)>=6:d['event']=parts[4].strip()
                elif m:d['event']=m[1]
            trace = d.get('trace_id') or d.get('requestId')
            if not trace:
                m = re.search(r'\btr-[\w-]+', line)
                trace = m[0] if m else ''
            if trace:
                key=(d.get('service') or d.get('function',''),d.get('instance',''),trace)
                context_keys={'lookup_key','match_key','subject_key','subject_ref','subject_reference','correlation_key','source'}
                if d.get('event','').endswith('_started'):
                    traces[key]={}
                previous=traces.setdefault(key,{})
                previous.update({k:v for k,v in d.items() if k in context_keys})
                d={**previous,**d}
            resource = d.get('resource_id')
            if not resource:
                continue
            # Started, retry, and cache messages do not establish resource state.
            event = d.get('event', '')
            if not event:
                event = next(iter(re.findall(r'\b(\w+(?:completed|read|lookup))\b', line)), '')
                d['event'] = event
            if event.endswith('_started') or event in ('cache_lookup','connection_acquired','dependency_retry','dependency_recovered'):
                continue
            if not (event.endswith('_completed') or event in ('record_lookup','message_pii_scan','connector_heartbeat','message_read','analytics_identity_scan','attachment_pii_scan','connector_config_loaded','analytics_profile_read','restore_candidate_evaluated','deletion_marker_check')):
                continue
            if event == 'attachment_pii_scan':
                d['record_type'] = 'SUPPORT_ATTACHMENT'
            if event in ('contact_query_completed','deletion_marker_check') and d.get('source')=='legacy_contact_index':
                d['record_type'] = 'SECONDARY_IDENTIFIER'
            if event == 'contact_lookup_completed':d['record_type'] = 'SECONDARY_IDENTIFIER'
            self.add(resource, d, item, at, d.get('system', ''), d.get('record_type', ''), text=json.dumps(d))
