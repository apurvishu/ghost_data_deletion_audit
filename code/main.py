"""Deterministic deletion-audit planner over participant-visible evidence only."""
from __future__ import annotations
import argparse
from collections import defaultdict, Counter
import hashlib
import json
from pathlib import Path
import re
import time
import unicodedata
import csv
from datetime import datetime
import platform

from extract import Evidence, IDENT, RESOURCE, Observation, read_csv, instant
from planning import OPERATIONS, FIELDS, ResourceDecision, PolicyRequirement, EvidenceProvenance, compile_plan, encode_result

ROOT = Path(__file__).resolve().parents[1]


def normalize(value):
    return unicodedata.normalize('NFKC', str(value)).strip().casefold()


def authorizes_deletion(text):
    """Explicit scope and negation precede positive multilingual deletion intent."""
    t = normalize(text).replace('’', "'")
    if re.search(r"(?:do not|don't|not a request to|without|never)\s+(?:delete|erase|remove|close)|marketing lists only|promotional emails|unsubscribe|opt.out", t):
        return False
    terms = ('delet','eras','remove my account','remove the profile','close my account','close this account','account closed','account closure','remove my profile','remove records','close the account','fully removed','already been removed','profile is gone','remove that search result','account was fully removed',
             'exclusão','eliminación','supprimer','suppression','削除','삭제','löschen','eliminar mi cuenta','apagar minha conta')
    return any(term in t for term in terms)


def leaves(value):
    if isinstance(value, dict):
        for k,v in value.items():
            if isinstance(v,(dict,list)): yield from leaves(v)
            else: yield k,v
    elif isinstance(value,list):
        for v in value: yield from leaves(v)


def truth(v):
    return v is True or str(v).casefold() in ('1','true','yes','allow','allowed','active','enabled')


def nonempty(v):
    return v is not None and normalize(v) not in ('','null','none','[redacted]','redacted','no direct identifier')


def resource_state(obs, identifiers=()):
    d = obs.data; cat = obs.category
    if cat=='ACCOUNT_TOMBSTONE' and d.get('reference_only') is True:return 'REDACTED'
    result = str(d.get('result','')).upper()
    identity_categories=('ANALYTICS_PROFILE','PRODUCT_TELEMETRY','SUPPORT_MESSAGE','ACCOUNT_TOMBSTONE','EMAIL_DELIVERY_LOG')
    contact_fields=('email','phone','email_hash','name','full_name','display_name','requester_name','requester_email','requester_phone','owner_email','owner_phone','customer_email','matched_value')
    payload=list(leaves(d))
    attributable=any(k in ('user_id','customer_reference','subject_reference') and nonempty(v) for k,v in payload)
    attributable |= any(k in ('source_resource_id','parent_resource_id') and isinstance(v,str)
                        and re.fullmatch(r'(?:account|secondary|tombstone|search|support|analytics)_\d+',v) for k,v in payload)
    def prose_pii(value):
        text=normalize(value)
        if re.search(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}|\b[a-f0-9]{64}\b|\+\d[\d ()-]{7,}\d',text):return True
        return any(' ' in v and not any(c.isdigit() for c in v) and re.search(r'(?<!\w)'+re.escape(v)+r'(?!\w)',text) for v in identifiers)
    # Payload fields outrank a summary label. A readback saying REDACTED while
    # exposing an email is evidence of exposure, not successful redaction.
    has_payload=any(k in contact_fields or k in ('message_text','message_excerpt') for k,v in payload)
    if result in ('NOT_FOUND','ABSENT','ANONYMIZED','REDACTED','DISABLED','BLOCKED') and not (cat in identity_categories and has_payload):
        return {'NOT_FOUND':'ABSENT'}.get(result,result)
    if result in ('FOUND','PRESENT','IDENTIFIABLE','ACTIVE') and not (cat in identity_categories and has_payload):
        return 'ACTIVE' if cat in ('DATA_FLOW','BACKUP_ARCHIVE') else 'PRESENT'
    if cat == 'DATA_FLOW':
        if 'enabled' in d: return 'ACTIVE' if truth(d['enabled']) else 'DISABLED'
    if cat == 'BACKUP_ARCHIVE':
        if 'restore_allowed' in d: return 'ACTIVE' if truth(d['restore_allowed']) else 'BLOCKED'
        if 'decision' in d: return 'BLOCKED' if d['decision']=='deny' else 'ACTIVE'
        if 'eligible' in d: return 'ACTIVE' if truth(d['eligible']) and not truth(d.get('deletion_block')) else 'BLOCKED'
    if str(d.get('status_code',d.get('http_status',''))) == '404': return 'ABSENT'
    if str(d.get('rows','')) == '0': return 'ABSENT'
    if cat == 'SEARCH_INDEX_ENTRY':
        if 'hits' in d and d['hits'].get('total')==0: return 'ABSENT'
        if result == 'MISS': return 'ABSENT'
    if cat in ('ANALYTICS_PROFILE','PRODUCT_TELEMETRY','SUPPORT_MESSAGE','ACCOUNT_TOMBSTONE','EMAIL_DELIVERY_LOG'):
        if 'direct_identifiers' in d:
            if str(d['direct_identifiers'])!='0':return 'PRESENT'
            actual_pii=any(k in contact_fields and nonempty(v) for k,v in payload) or any(
                k in ('message_text','message_excerpt') and nonempty(v) and prose_pii(v) for k,v in payload)
            if cat in ('ANALYTICS_PROFILE','PRODUCT_TELEMETRY'):
                actual_pii |= attributable
            if not actual_pii:return 'ANONYMIZED' if cat in ('ANALYTICS_PROFILE','PRODUCT_TELEMETRY') else 'REDACTED'
        if d.get('event') in ('analytics_identity_scan','message_pii_scan'): return 'PRESENT'
        if d.get('marker_found')=='false':return 'PRESENT'
        direct_fields = contact_fields
        flat = list(leaves(d))
        exposed = any(k in direct_fields and nonempty(v) for k,v in flat)
        exposed |= any(k in ('message_text','message_excerpt') and nonempty(v) and prose_pii(v) for k,v in flat)
        if cat in ('ANALYTICS_PROFILE','PRODUCT_TELEMETRY'):
            exposed |= attributable
        if 'document_text' in d:
            # Business screenshots/documents with a visible direct identifier.
            exposed = bool(re.search(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}',d['document_text']))
        if not exposed and any(k in direct_fields or k in ('user_id','customer_reference','subject_reference') for k,v in flat):
            return 'ANONYMIZED' if cat in ('ANALYTICS_PROFILE','PRODUCT_TELEMETRY') else 'REDACTED'
    return 'PRESENT'


class Auditor:
    def __init__(self, dataset):
        self.dataset = Path(dataset)
        self.identities = read_csv(self.dataset/'user_identities.csv')
        self.history = read_csv(self.dataset/'user_audit_log.csv')
        self.activity = read_csv(self.dataset/'system_activity.csv')
        self.policy_rules = {r['data_category']:r for r in read_csv(self.dataset/'deletion_rules.csv')}
        self.policy = {category:row['required_action'] for category,row in self.policy_rules.items()}
        self.evidence = Evidence(self.dataset)
        self.by_resource = defaultdict(list)
        for o in self.evidence.observations:self.by_resource[o.resource].append(o)
        self.last_decisions=()
        self.last_exclusions=[]

    def identifiers(self,email,cutoff):
        requested = normalize(email)
        users = {r['user_id'] for r in self.identities if normalize(r['email'])==requested and instant(r['updated_at'])<=instant(cutoff)}
        users |= {r['user_id'] for r in self.history if instant(r['event_time'])<=instant(cutoff) and r['field_name']=='email' and requested in (normalize(r['old_value']),normalize(r['new_value']))}
        if len(users)!=1:
            raise ValueError(f'Expected one subject, found {len(users)}')
        values = set(users)|{requested}
        for row in self.identities:
            if row['user_id'] in users and instant(row['updated_at'])<=instant(cutoff):
                values.update(normalize(row[k]) for k in ('name','email','phone','email_hash') if row.get(k))
        for row in self.history:
            if row['user_id'] in users and instant(row['event_time'])<=instant(cutoff) and row['field_name'] in ('name','email','phone','email_hash'):
                values.update((normalize(row['old_value']),normalize(row['new_value'])))
        # Hashes of historical addresses can survive in analytics stores.
        values |= {hashlib.sha256(v.encode()).hexdigest() for v in list(values) if '@' in v}
        return {v for v in values if v}

    @staticmethod
    def matches(text, identifiers):
        tokens = {normalize(x) for x in IDENT.findall(text)}
        if tokens & identifiers:return True
        # Exact normalized field values, not substrings of another person's identifiers.
        return any(len(v)>5 and '@' not in v and not v.startswith('user_') and re.search(r'(?<!\w)'+re.escape(v)+r'(?!\w)',normalize(text)) for v in identifiers)

    def audit(self, request):
        self.last_decisions=()
        self.last_exclusions=[]
        if not authorizes_deletion(request['request_text']):return encode_result(request['case_id'],'NOT_APPLICABLE',[])
        cutoff = request['audit_at']; ids = self.identifiers(request['email'],cutoff)
        cutoff_time=instant(cutoff)
        visible = [o for o in self.evidence.observations if instant(o.at)<=cutoff_time and instant(o.available)<=cutoff_time
                   and (not o.link_available or instant(o.link_available)<=cutoff_time)]
        # Non-unique names cannot establish ownership, but remain prohibited PII
        # in a record already linked through its stable subject reference.
        names=Counter(normalize(row['name']) for row in self.identities)
        ownership_ids=ids-{name for name,count in names.items() if count>1}
        pattern = re.compile(r'(?<![\w@.+-])(?:'+'|'.join(re.escape(v) for v in sorted(ownership_ids,key=len,reverse=True))+r')(?![\w@.+-])',re.I)
        def matches(text):return bool(pattern.search(unicodedata.normalize('NFKC',text)))
        def ownership_text(o):
            if o.identity_text:return o.identity_text
            if 'document_text' not in o.data:
                owner_keys={'user_id','customer_reference','subject_reference','subject_selector','email','email_hash','phone','owner_email','owner_phone','customer_email','requester_email','requester_phone','matched_value'}
                owners={k:v for k,v in leaves(o.data) if k in owner_keys and nonempty(v)}
                # A query may return somebody else's similar address. Concrete
                # record ownership outranks the lookup query when it is present.
                return json.dumps(owners,ensure_ascii=False) if owners else o.text
            links=[a for a in self.evidence.catalog.get(o.resource,[]) if instant(a['event_time'])<=cutoff_time]
            if links:return '\n'.join(a['details'] for a in links)
            # Do not bind a selected record to every customer mentioned in a UI table.
            emails={normalize(t) for t in IDENT.findall(o.text) if '@' in t}
            subjects={normalize(t) for t in IDENT.findall(o.text) if t.startswith('user_')}
            if len(emails)>1 or len(subjects)>1:return ''
            return o.text if len(set(RESOURCE.findall(o.text)))==1 else ''
        resources=set();identity_links=defaultdict(set)
        def link(resource,evidence_id,basis):
            resources.add(resource);identity_links[resource].add((evidence_id,basis))
        for o in visible:
            if matches(ownership_text(o)):
                link(o.resource,o.evidence,'CURRENT_OR_HISTORICAL_IDENTIFIER_MATCH')
                for catalog_link in self.evidence.catalog.get(o.resource,[]):
                    if instant(catalog_link['event_time'])<=cutoff_time and matches(catalog_link['details']):
                        identity_links[o.resource].add((catalog_link['activity_id'],'CATALOG_IDENTITY_LINK'))
        for a in self.activity:
            if instant(a['event_time'])<=cutoff_time and matches(a['details']):link(a['resource_id'],a['activity_id'],'ACTIVITY_IDENTITY_LINK')
        # A unique primary deletion event adjacent to the workflow report identifies
        # the workflow target; its SUCCESS/FAILED claim is never used as state proof.
        report = datetime.fromisoformat(request['reported_at'].replace('Z','+00:00'))
        near = [a for a in self.activity if instant(a['event_time'])<=cutoff_time and a['event_type']=='DELETE_RECORD' and a['target_system']=='account_service' and 0 <= (report-instant(a['event_time'])).total_seconds()<=60]
        if not near and not any(r.startswith('account_') for r in resources):
            near = [a for a in self.activity if instant(a['event_time'])<=cutoff_time and a['event_type']=='DELETE_RECORD' and a['target_system']=='account_service' and abs((report-instant(a['event_time'])).total_seconds())<=600]
        if len(near)==1 and not any(r.startswith('account_') for r in resources):link(near[0]['resource_id'],near[0]['activity_id'],'UNIQUE_REPORT_TIME_TARGET')
        # Follow the bounded workflow episode anchored to an identified resource.
        workers = sorted([a for a in self.activity if a['source_system']=='deletion_worker' and instant(a['event_time'])<=cutoff_time],key=lambda a:(instant(a['event_time']),a['activity_id']))
        for n,a in enumerate(workers):
            if a['event_type']=='DELETE_RECORD' and a['target_system']=='account_service' and a['resource_id'] in resources:
                start = datetime.fromisoformat(a['event_time'].replace('Z','+00:00'))
                anonymous=defaultdict(set)
                for b in workers[n+1:]:
                    if b['event_type']=='DELETE_RECORD' and b['target_system']=='account_service':break
                    if (datetime.fromisoformat(b['event_time'].replace('Z','+00:00'))-start).total_seconds()>2700:break
                    related = [o for o in visible if o.resource==b['resource_id'] and 'document_text' not in o.data]
                    known = [o for o in related if IDENT.search(ownership_text(o))]
                    if any(matches(ownership_text(o)) for o in known):link(b['resource_id'],b['activity_id'],'WORKFLOW_TARGET_WITH_IDENTIFIER_MATCH')
                    elif not known:anonymous[b['event_type']].add(b['resource_id'])
                # Job proximity is insufficient when two anonymous targets are
                # equally plausible. Never resolve that tie by resource ID order.
                for candidates in anonymous.values():
                    if len(candidates)==1:
                        for resource in candidates:link(resource,a['activity_id'],'UNIQUE_WORKFLOW_EPISODE')
                    elif candidates:
                        self.last_exclusions.extend(dict(resource_id=resource,reason='AMBIGUOUS_WORKFLOW_OWNERSHIP') for resource in sorted(candidates))
        # Source-resource references connect a discovered downstream copy to its
        # source without assigning every identifier in a multi-record document.
        owner_fields={'user_id','customer_reference','subject_reference','subject_selector','email','email_hash','phone','owner_email','owner_phone','customer_email','requester_email','requester_phone','matched_value'}
        def compatible_owner(resource):
            owners=[o for o in visible if o.resource==resource and (o.identity_text or any(k in owner_fields and nonempty(v) for k,v in leaves(o.data)))]
            if not owners:return True
            newest=max(instant(o.at) for o in owners)
            return any(matches(ownership_text(o)) for o in owners if instant(o.at)==newest)
        changed=True
        while changed:
            before=len(resources)
            for o in visible:
                for key,value in leaves(o.data):
                    if key in ('source_resource_id','parent_resource_id') and isinstance(value,str) and RESOURCE.fullmatch(value):
                        if o.resource in resources and compatible_owner(value):link(value,o.evidence,'EXPLICIT_SOURCE_REFERENCE')
                        if value in resources and compatible_owner(o.resource):link(o.resource,o.evidence,'EXPLICIT_SOURCE_REFERENCE')
            for activity in self.activity:
                if activity['event_type']=='RESTORE_BACKUP' and activity['resource_id'] in resources and instant(activity['event_time'])<=cutoff_time:
                    destination=re.search(r'\bdownstream resource\s+(\w+_\d+)\b',activity['details'])
                    if destination and RESOURCE.fullmatch(destination[1]) and compatible_owner(destination[1]):
                        link(destination[1],activity['activity_id'],'EXPLICIT_RESTORE_DESTINATION')
            changed=len(resources)>before
        # Scope-only negative lookups must not rejuvenate a resource that was
        # already gone before this request. Determine relevance from original
        # observations before synthesizing any new negative lookup.
        for resource in list(resources):
            old={}
            for o in visible:
                if o.resource==resource:
                    copy=o.copy or 'readback'
                    if copy not in old or instant(o.at)>instant(old[copy].at):old[copy]=o
            if not old or any(instant(o.at)>=instant(request['requested_at']) or resource_state(o,ids)!='ABSENT' for o in old.values()):continue
            touched=any(a['resource_id']==resource and instant(request['requested_at'])<=instant(a['event_time'])<=cutoff_time for a in self.activity)
            referenced=any(o.resource in resources and instant(o.at)>=instant(request['requested_at']) and any(
                key in ('source_resource_id','parent_resource_id') and value==resource for key,value in leaves(o.data)) for o in visible)
            if not touched and not referenced:
                resources.remove(resource);self.last_exclusions.append(dict(resource_id=resource,reason='ALREADY_ABSENT_BEFORE_REQUEST_WITHOUT_CURRENT_LINK'))
        for resource in list(resources):
            if resource.startswith('account_'):
                related_files = {o.evidence for o in visible if o.resource in resources}
                scopes = [s for s in self.evidence.scopes if s[0]=='account_service' and instant(s[1])<=cutoff_time and instant(s[2])<=cutoff_time and resource not in s[4] and (s[3] in related_files or s[3] in self.evidence.complete_account_files)
                          and not any(x.resource==resource and x.evidence==s[3] and resource_state(x)!='ABSENT' for x in visible)]
                # A replica containing the record still takes precedence below.
                for system,at,available,eid,present in scopes:
                    visible.append(Observation(resource,system,'USER_PROFILE',at,available,eid,{'result':'NOT_FOUND'},'',copy='negative_snapshot'))
        decisions=[]
        for resource in sorted(resources):
            candidates = [o for o in visible if o.resource==resource]
            if not candidates:
                self.last_exclusions.append(dict(resource_id=resource,reason='NO_PRE_CUTOFF_RESOURCE_STATE'))
                continue
            exemplar=candidates[0]
            if self.policy.get(exemplar.category)=='DELETE':
                # An explicit later snapshot can clear a previously observed copy.
                # This is separate from a primary readback, which cannot clear it.
                for system,copy,at,available,eid,present in self.evidence.copy_scopes:
                    if system==exemplar.system and resource not in present and instant(at)<=cutoff_time and instant(available)<=cutoff_time:
                        if any(c.copy==copy and instant(c.at)<=instant(at) for c in candidates):
                            candidates.append(Observation(resource,system,exemplar.category,at,available,eid,{'result':'NOT_FOUND'},'',copy))
            # Most recent observation for each independently captured copy.
            latest = {}
            for o in candidates:
                copy = o.copy or 'readback'
                if copy not in latest or (instant(o.at),instant(o.available),o.evidence)>(instant(latest[copy].at),instant(latest[copy].available),latest[copy].evidence):latest[copy]=o
            newest_at = max(instant(o.at) for o in candidates)
            current = [o for o in latest.values() if instant(o.at)==newest_at]
            # Prefer a concrete record over a readback when equally recent; replica violations win.
            o = max(current,key=lambda x:(resource_state(x,ids) in ('PRESENT','ACTIVE'), x.copy!='',x.evidence))
            # A newer primary readback cannot prove that a separately captured
            # replica was cleaned. Keep independently observed replica drift.
            replicas = [x for x in latest.values() if 'replica' in x.copy and resource_state(x,ids)=='PRESENT']
            if replicas:o=max(replicas,key=lambda x:(instant(x.at),x.evidence))
            state = resource_state(o,ids); cat=o.category; action=self.policy.get(cat)
            if cat=='DATA_FLOW':action='DISABLE'
            if cat=='BACKUP_ARCHIVE':action='BLOCK'
            row=self.policy_rules.get(cat)
            requirement=PolicyRequirement(row['rule_id'],cat,row['condition'],row['required_action']) if row else PolicyRequirement('',cat,'No active process may recreate prohibited data',action,'AGENTS.md section 6.5 / problem_statement.md')
            proof=EvidenceProvenance(o.evidence,o.at,o.available,o.link_available,o.copy,
                'RESOURCE_OBSERVATION' if o.text else 'SNAPSHOT_NEGATIVE_LOOKUP')
            decisions.append(ResourceDecision(o.system,resource,action,state,o.evidence,requirement,(proof,),tuple(sorted(identity_links[resource]))))
        self.last_decisions=tuple(decisions)
        status,steps=compile_plan(decisions)
        return encode_result(request['case_id'],status,steps)


def write_output(rows,path):
    with Path(path).open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['case_id','deletion_status','steps_json'],lineterminator='\n');writer.writeheader();writer.writerows(sorted(rows,key=lambda x:x['case_id']))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',type=Path,default=ROOT/'dataset')
    parser.add_argument('--requests',default='deletion_requests.csv')
    parser.add_argument('--output',type=Path,default=ROOT/'output.csv')
    args=parser.parse_args(); start=time.perf_counter()
    auditor=Auditor(args.dataset);requests=read_csv(args.dataset/args.requests)
    rows=[auditor.audit(r) for r in requests];write_output(rows,args.output)
    elapsed=time.perf_counter()-start
    if args.requests=='deletion_requests.csv':
        images=sum(Path(item['file_path']).suffix=='.png' for item in auditor.evidence.manifest)
        report=f'''# Final full-dataset run usage

Generated {len(rows)} requests in {elapsed:.2f} seconds on Python {platform.python_version()}.
Output SHA-256: `{hashlib.sha256(args.output.read_bytes()).hexdigest()}`.
Run timestamp (with timezone): {datetime.now().astimezone().isoformat()}.

| Provider / model | Calls | Input tokens | Output tokens | Total tokens | Tokens/request | Estimated cost | Cost/request |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| LLM providers / none invoked | 0 | 0 | 0 | 0 | 0 | $0 | $0 |
| Microsoft / Windows.Media.Ocr OS language recognizer | {images if platform.system()=='Windows' else 0} | 0 | 0 | 0 | 0 | $0 | $0 |
| Overall | {images if platform.system()=='Windows' else 0} | 0 | 0 | 0 | 0 | $0 | $0 |

The final run uses local OCR inference for screenshot text and deterministic Python
for retrieval, policy reasoning and planning. OCR has no language-model token billing;
zero here means no billed tokens, not zero image processing. The OS recognizer's
underlying weight/version identifier is not exposed by this API. On non-Windows
systems the documented Tesseract executable replaces Windows OCR (one call/image).
No hosted model, credentials, or paid inference API is required.

There are {images} screenshot files, {sum(Path(i['file_path']).suffix=='.pdf' for i in auditor.evidence.manifest)} PDF files,
and {len(auditor.evidence.observations)} normalized observations. Each screenshot is
read once per run, then reused for all requests. PDF, SQL, JSON and log parsing has
no model token usage. Total/average input and output tokens are all zero for the
final dataset run. Monetary cost is external inference cost; local electricity and
hardware are not estimated. Development assistant usage is separate from this run
and has not been measured or represented as free.
'''
        path=Path(__file__).parent/'evaluation/usage_report.md';path.parent.mkdir(exist_ok=True);path.write_text(report,encoding='utf-8',newline='\n')
    print(f'Wrote {len(rows)} cases to {args.output} in {elapsed:.2f}s')


if __name__=='__main__':main()
