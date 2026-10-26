# Ghost Data Still Exists - deletion-audit agent

This offline auditor reads participant-facing files in `dataset/`, reconstructs
identity and resource state at each `audit_at`, applies `deletion_rules.csv`, and
writes ordered audit proposals to root `output.csv`. It never changes source data
or performs deletion. Local Windows OCR supplies the machine-learning component;
policy decisions and serialization are deterministic Python, with no hosted LLM.

## Setup and run

Use Python 3.10 or later. On Windows, Windows PowerShell and an installed English
Windows OCR language recognizer are required. No API key is needed.

```powershell
python code/main.py
python code/evaluation/validate.py
python code/evaluation/main.py --run-tests
python -m unittest discover -s code -p "test_*.py" -v
python code/package.py
python code/verify_submission.py
```

The supplied PDFs have a standard-library text extractor. For broader PDF support,
optionally install `python -m pip install -r code/requirements.txt` in your own
virtual environment. Linux/macOS additionally need the `tesseract` executable on
PATH for screenshots; OCR versions can produce different text. The verified run
used Windows OCR. No runtime network access is required.

Run from any working directory; default paths resolve from the source location.
Custom paths are supported:

```text
python code/main.py --dataset /path/to/dataset --output /path/to/output.csv
```

Keep `dataset/` beside the extracted `code/` folder for the default command.
Prediction does not read `sample_output.csv`; the evaluation command reads it only
once all public-sample predictions have been made. A sample with insufficient
identity/state evidence is counted as an abstention rather than assigned an answer.

## Architecture

- `code/extract.py`: manifest path checks, JSON and text normalization, in-memory
  SQLite snapshots, trace-ID log joins, PDF extraction, and local screenshot OCR.
- `code/main.py`: multilingual consent scope, historical identities and hashes,
  resource matching, cutoff filtering, independent replica observations, policy
  application, canonical step ordering, CSV output, and final-run usage accounting.
- `code/planning.py`: one deterministic policy-to-operation map, seven-field schema,
  canonical ordering, proof rules, duplicate/conflict guards, and serialization.
- `code/test_auditor.py`: independent adversarial and second-pass regression tests.
- `code/evaluation/main.py`: public status, exact step, positional field, and ordered
  sequence metrics, failure analysis, and participant-created evaluation cases.
- `code/evaluation/ranked_error_analysis.md`: ranked content/field disagreements for
  every failing public sample; index shifts are separated from actual field errors.
- `code/evaluation/verification_coverage.md`: policy/provenance ledger for every
  accepted decision, missing-check gates, extra-step lineage, and abstention audit.
- `code/evaluation/validate.py`: coverage, types, operation/state pairs, ordering,
  citation existence and cutoff, duplicate detection, and remediation verification.
- `code/package.py`: repeatable allowlist packaging and archive integrity checks.
- `code/verify_submission.py`: extracts the final archive and requires a byte-for-byte
  match from its full dataset run, without the local dependency directory.

Manifest and embedded timestamps are both enforced. Workflow results are never
accepted as resource-state proof. Catalog aliases can connect business documents
to resource IDs. Where a subject has no remaining identifiers, bounded workflow-time
correlation is an explicit heuristic; overlapping jobs and unlinked anonymized
records remain limitations. Ordinary PDF/image interpretation is conservative.
Strict cutoff handling can disagree with public answers that cite later exports.
Read the generated evaluation report before relying on these predictions.

The second pass narrows document aliases and screen ownership, separates lookup
context from actual readback fields, handles timezone offsets as instants, and
allows explicit later replica snapshots to clear earlier drift. Payload identifiers
override summary compliance labels. Anonymous job targets are left unassigned when
multiple candidates are equally plausible. The report audits every remaining public
mismatch and distinguishes absent input identifiers from extraction gaps.

The accuracy pass preserves its original artifacts under `build/accuracy-pass-*/`.
It adds tested sequence-contract guards, bidirectional explicit source links and
restore-destination retrieval without trusting workflow success as presence proof.
Public accuracy did not increase in this pass; the verified answer content is
retained. See `code/evaluation/accuracy_pass.md` for the measured decision record.

To reproduce the local before/after comparison while the saved baseline is present:

```text
python code/evaluation/main.py --baseline build/second-pass/baseline_predictions.json --run-tests
```

Baseline predictions are evaluation-only and are excluded from `code.zip`. The
ordinary evaluation command works independently of that development artifact.

The output contains exactly the request case IDs in lexicographic order, with the
required three columns and consecutive JSON step numbers. An incomplete case
includes evidence-backed findings, risk controls before record treatment, and final
checks. A complete case includes only cited verification. Non-deletion requests
produce `NOT_APPLICABLE` and `[]`.

## Artifacts and evaluation

`python code/main.py` generates `output.csv` and
`code/evaluation/usage_report.md`. `python code/evaluation/main.py` generates
`code/evaluation/evaluation_report.md`, including measured accuracy and known
failures. Semantic accuracy on the 518 evaluation cases cannot be measured without
hidden answers and is not claimed. The usage report accounts for the final dataset
run, separately from development assistant usage.

`python code/package.py` creates `code.zip` with runnable source, this README,
requirements, and reports under both `code/evaluation/` and `evaluation/` for
compatibility with the repository's two documented layouts. Dataset, output,
transcripts, caches, dependency directories, credentials, and nested archives are
excluded. Submit root `output.csv` and root `log.txt` separately.

## Session trace

The append-only `log.txt` is the required conversation transcript. The raw Codex
rollout is still being written during the session. After the session finishes,
close Codex, review and redact only this challenge's rollout JSONL, then run:

```powershell
powershell -File code/trace_after_exit.ps1 -ReviewedRolloutPath "C:\path\to\reviewed-rollout.jsonl"
```

This creates a separate `agent-trace.zip`; do not include it inside `code.zip`.
Never stage authentication files, settings, unrelated sessions, or credentials.
See `agent_trace_instructions.md` for the complete trace instructions.

## Challenge

The October challenge end time is not configured in the repository.
Submit at https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists.
The original specification remains in `problem_statement.md`; repository agent and
transcript requirements remain in `AGENTS.md`.
