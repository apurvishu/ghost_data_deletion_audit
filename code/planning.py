"""The single deterministic policy-to-step, ordering, and serialization contract."""
from dataclasses import dataclass, asdict
import json

OPERATIONS = {
    'FINDING': [('REPORT_REMAINING_RECORD','PRESENT'),('REPORT_EXPOSED_PII','PRESENT'),('REPORT_ACTIVE_DATA_FLOW','ACTIVE'),('REPORT_RESTORE_RISK','ACTIVE')],
    'REMEDIATION': [('DISABLE_DATA_FLOW','DISABLED'),('BLOCK_RESTORE','BLOCKED'),('DELETE_RECORD','ABSENT'),('REDACT_RECORD','REDACTED'),('ANONYMIZE_RECORD','ANONYMIZED')],
    'VERIFICATION': [('VERIFY_RECORD_ABSENT','ABSENT'),('VERIFY_RECORD_PRESENT','PRESENT'),('VERIFY_RECORD_REDACTED','REDACTED'),('VERIFY_RECORD_ANONYMIZED','ANONYMIZED'),('VERIFY_DATA_FLOW_DISABLED','DISABLED'),('VERIFY_RESTORE_BLOCKED','BLOCKED')],
}
FIELDS = ['step_no','phase','system_id','resource_id','operation','state','evidence_id']
# Required state, finding, remediation, verification. RETAIN has no permitted repair
# for a missing record, so that condition must remain explicitly unresolved.
POLICY = {
    'DELETE': ('ABSENT','REPORT_REMAINING_RECORD','DELETE_RECORD','VERIFY_RECORD_ABSENT'),
    'REDACT': ('REDACTED','REPORT_EXPOSED_PII','REDACT_RECORD','VERIFY_RECORD_REDACTED'),
    'ANONYMIZE': ('ANONYMIZED','REPORT_EXPOSED_PII','ANONYMIZE_RECORD','VERIFY_RECORD_ANONYMIZED'),
    'RETAIN': ('PRESENT',None,None,'VERIFY_RECORD_PRESENT'),
    'DISABLE': ('DISABLED','REPORT_ACTIVE_DATA_FLOW','DISABLE_DATA_FLOW','VERIFY_DATA_FLOW_DISABLED'),
    'BLOCK': ('BLOCKED','REPORT_RESTORE_RISK','BLOCK_RESTORE','VERIFY_RESTORE_BLOCKED'),
}
VERIFY_FOR={repair:verify for desired,finding,repair,verify in POLICY.values() if repair}
FINDINGS_FOR={}
for desired,finding,repair,verify in POLICY.values():
    if finding:FINDINGS_FOR.setdefault(finding,set()).add(repair)


@dataclass(frozen=True)
class PolicyRequirement:
    rule_id: str
    data_category: str
    condition: str
    required_action: str
    source: str = 'deletion_rules.csv'


@dataclass(frozen=True)
class EvidenceProvenance:
    evidence_id: str
    observed_at: str = ''
    captured_at: str = ''
    identity_linked_at: str = ''
    copy: str = ''
    proof_kind: str = 'RESOURCE_OBSERVATION'


@dataclass(frozen=True)
class ResourceDecision:
    system_id: str
    resource_id: str
    action: str
    observed_state: str
    evidence_id: str
    policy_requirement: PolicyRequirement | None = None
    provenance: tuple[EvidenceProvenance, ...] = ()
    identity_links: tuple[tuple[str,str], ...] = ()

    def __post_init__(self):
        # Legacy callers can provide a resolved action without source metadata.
        # Missing metadata stays explicitly unknown; IDs/timestamps are never made up.
        if not self.provenance:
            object.__setattr__(self,'provenance',(EvidenceProvenance(self.evidence_id),))
        if not any(p.evidence_id==self.evidence_id for p in self.provenance):
            raise ValueError('Decision proof is absent from its evidence provenance')
        if self.policy_requirement and self.policy_requirement.required_action!=self.action:
            backup_control=(self.policy_requirement.data_category=='BACKUP_ARCHIVE' and self.policy_requirement.required_action=='RETAIN' and self.action=='BLOCK')
            if not backup_control:raise ValueError('Decision treatment contradicts its policy requirement')

    @property
    def required_treatment(self):return self.action

    @property
    def required_state(self):return POLICY[self.action][0]

    @property
    def verification_operation(self):return POLICY[self.action][3]

    @property
    def outstanding_conditions(self):
        return () if self.observed_state==self.required_state else ('REQUIRED_STATE:'+self.required_state,)

    def coverage_record(self,status):
        return dict(system_id=self.system_id,resource_id=self.resource_id,
            required_treatment=self.required_treatment,required_state=self.required_state,
            observed_state=self.observed_state,policy_requirement=asdict(self.policy_requirement) if self.policy_requirement else None,
            evidence_provenance=[asdict(p) for p in self.provenance],identity_links=list(self.identity_links),
            outstanding_conditions=list(self.outstanding_conditions),verification_operation=self.verification_operation,
            verification_evidence_id=self.evidence_id if status=='COMPLETE' else '',
            verification_timing='CURRENT_PROOF' if status=='COMPLETE' else 'AFTER_REMEDIATION')


def validate_verification_coverage(decisions,status,steps):
    """Exactly the policy-required checks for accepted decisions, without guessing resources."""
    required={(d.system_id,d.resource_id,d.verification_operation,d.required_state,
               d.evidence_id if status=='COMPLETE' else '') for d in decisions}
    actual={(s['system_id'],s['resource_id'],s['operation'],s['state'],s['evidence_id'])
            for s in steps if s['phase']=='VERIFICATION'}
    if required-actual:raise ValueError('Verification coverage gap for an accepted resource decision')
    if actual-required:raise ValueError('Verification for an unrelated or unrequired resource')


def step_key(step):
    return (list(OPERATIONS).index(step['phase']),
            [operation for operation,state in OPERATIONS[step['phase']]].index(step['operation']),
            step['system_id'],step['resource_id'])


def validate_steps(status,steps):
    """Validate shape, evidence rules, contradictions and bidirectional coverage."""
    def require(condition,message):
        if not condition:raise ValueError(message)
    require(status in ('COMPLETE','INCOMPLETE','NOT_APPLICABLE'),'Invalid deletion status')
    require(isinstance(steps,list),'Steps must be a JSON array')
    if status=='NOT_APPLICABLE':
        require(not steps,'NOT_APPLICABLE requires an empty array');return
    require(bool(steps),'Authorized requests require verified resource states')
    seen=set();by_phase={phase:{} for phase in OPERATIONS};keys=[]
    for n,step in enumerate(steps,1):
        require(isinstance(step,dict) and set(step)==set(FIELDS),'Each step must contain exactly seven fields')
        require(type(step['step_no']) is int and step['step_no']==n,'Step numbers must be consecutive integers')
        require(all(isinstance(step[k],str) for k in FIELDS if k!='step_no'),'Step fields must be strings')
        phase=step['phase'];require(phase in OPERATIONS,'Invalid phase')
        require((step['operation'],step['state']) in OPERATIONS[phase],'Invalid operation/state pair')
        require(step['system_id'] and step['resource_id'],'Empty system or resource ID')
        identity=(step['system_id'],step['resource_id']);signature=(phase,*identity,step['operation'])
        require(signature not in seen,'Duplicate steps');seen.add(signature)
        by_phase[phase].setdefault(identity,set()).add(step['operation'])
        keys.append(step_key(step))
        if status=='COMPLETE':require(phase=='VERIFICATION','COMPLETE permits verification only')
        if status=='COMPLETE' or phase=='FINDING':require(bool(step['evidence_id']),'Current proof needs an evidence reference')
        else:require(step['evidence_id']=='','Future work must not cite existing evidence')
    require(keys==sorted(keys),'Incorrect phase/operation/system/resource order')
    for identity,operations in by_phase['VERIFICATION'].items():
        if 'VERIFY_RECORD_ABSENT' in operations:
            require(not operations & {'VERIFY_RECORD_PRESENT','VERIFY_RECORD_REDACTED','VERIFY_RECORD_ANONYMIZED'},'Contradictory record verification')
    for identity,operations in by_phase['REMEDIATION'].items():
        require(len(operations & {'DELETE_RECORD','REDACT_RECORD','ANONYMIZE_RECORD'})<=1,'Contradictory record remediation')
    if status=='INCOMPLETE':
        require(bool(by_phase['FINDING']) and bool(by_phase['REMEDIATION']),'Incomplete cases need findings and remediation')
        for identity,findings in by_phase['FINDING'].items():
            repairs=by_phase['REMEDIATION'].get(identity,set())
            for finding in findings:require(bool(repairs & FINDINGS_FOR[finding]),'Finding lacks remediation')
        for identity,repairs in by_phase['REMEDIATION'].items():
            findings=by_phase['FINDING'].get(identity,set())
            checks=by_phase['VERIFICATION'].get(identity,set())
            for repair in repairs:
                require(any(repair in FINDINGS_FOR[finding] for finding in findings),'Remediation lacks a supporting finding')
                require(VERIFY_FOR[repair] in checks,'Unverified remediation')


def compile_plan(decisions):
    """Consume resolved policy decisions; discovery never creates output operations."""
    resolved={}
    for decision in decisions:
        if decision.action not in POLICY:raise ValueError('Unknown policy action')
        if decision.observed_state not in ('PRESENT','ABSENT','REDACTED','ANONYMIZED','ACTIVE','DISABLED','BLOCKED'):
            raise ValueError('Unverified resource state cannot be planned')
        if not all((decision.system_id,decision.resource_id,decision.evidence_id)):raise ValueError('Decision lacks identity or proof')
        identity=(decision.system_id,decision.resource_id)
        old=resolved.get(identity)
        if old:
            if (old.action,old.observed_state)!=(decision.action,decision.observed_state):
                raise ValueError('Conflicting resource decisions must be resolved before planning')
            # Keep proof metadata with the selected proof rather than replacing
            # only its ID and accidentally attaching another capture's provenance.
            decision=min((old,decision),key=lambda d:d.evidence_id)
        resolved[identity]=decision
    if not resolved:raise ValueError('No grounded resource state for authorized request')
    incomplete=any(d.observed_state!=POLICY[d.action][0] for d in resolved.values())
    status='INCOMPLETE' if incomplete else 'COMPLETE';steps=[]
    def add(d,phase,operation,state,evidence=''):
        steps.append(dict(step_no=0,phase=phase,system_id=d.system_id,resource_id=d.resource_id,
                          operation=operation,state=state,evidence_id=evidence))
    for decision in resolved.values():
        desired,finding,repair,verification=POLICY[decision.action]
        if decision.observed_state!=desired:
            if not repair:raise ValueError('Required retained resource missing; contract has no create operation')
            add(decision,'FINDING',finding,'ACTIVE' if decision.action in ('DISABLE','BLOCK') else 'PRESENT',decision.evidence_id)
            add(decision,'REMEDIATION',repair,desired)
        add(decision,'VERIFICATION',verification,desired,'' if incomplete else decision.evidence_id)
    steps.sort(key=step_key)
    for number,step in enumerate(steps,1):step['step_no']=number
    validate_steps(status,steps)
    validate_verification_coverage(resolved.values(),status,steps)
    return status,steps


def encode_result(case_id,status,steps):
    validate_steps(status,steps)
    return dict(case_id=case_id,deletion_status=status,steps_json=json.dumps(steps,separators=(',',':'),ensure_ascii=False))
