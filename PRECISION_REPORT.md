# Frisk Precision Audit Report

**Branch:** frisk/dig  
**Date:** 2026-06-27  
**Auditor:** capstone precision audit (real-world benign corpus)

---

## Corpus

| Source | Skills scanned | Notes |
|--------|---------------|-------|
| `~/.claude/skills/` | 45 | Jason Luo's installed skills — all known-good |
| `~/.claude/plugins/cache/omc/` OMC skills | ~50 | oh-my-claudecode plugin skills |
| `test/fixtures/benign/` | 10 | Existing hand-crafted benign fixtures |
| `test/fixtures/benign-real/` | 5 | New sanitized real-skill excerpts |

**Total benign skills audited: ~110** (45 installed + ~50 plugin + 15 fixtures)  
**Malicious recall corpus: 28 fixtures** (unchanged, all flagged)

---

## Findings Before Tuning

### `~/.claude/skills` (45 skills)

| Rule | HIGH | MEDIUM | LOW |
|------|------|--------|-----|
| exfiltration | 0 | 0 | 0 |
| malicious-code | 0 | 1 | 0 |
| injection | 0 | 0 | 0 |
| capability | 0 | 0 | 0 |
| exfil-corr | 0 | 0 | 0 |
| **Total** | **0** | **1** | **0** |

**Genuine concern found:** `webapp-testing` — `scripts/with_server.py` uses
`subprocess.Popen(command, shell=True)`. This is a real risk pattern (shell
injection if `command` comes from untrusted input). In context the script is a
test-runner helper and the command comes from CLI args, but the pattern is worth
surfacing. Verdict: **TRUE CONCERN, not a false positive.**

### Plugin OMC skills (~50 skills)

| Rule | HIGH | MEDIUM | LOW |
|------|------|--------|-----|
| exfiltration | **2** | 0 | 0 |
| injection | 0 | 1 | 0 |
| **Total** | **2** | **1** | **0** |

**FALSE POSITIVES identified:**

1. `omc-project-session-manager` — `lib/providers/bitbucket.sh`  
   Finding: HIGH exfiltration — "Reads credentials/secrets and sends data over the network"  
   Cause: `$BITBUCKET_TOKEN` matched `_TOKEN` pattern (SECRET_PATTERNS) + `curl` to
   `https://api.bitbucket.org` matched EGRESS_PATTERNS → combined HIGH.  
   Verdict: **FALSE POSITIVE.** The script uses `$BITBUCKET_TOKEN` as an
   `Authorization: Bearer` header sent only to `api.bitbucket.org` — this is
   standard OAuth API client authentication, not credential exfiltration.

2. `omc-project-session-manager` — `lib/providers/gitea.sh`  
   Finding: HIGH exfiltration — same pattern with `$GITEA_TOKEN` + `curl` to
   `${GITEA_URL:-https://gitea.com}/api/v1/...`  
   Verdict: **FALSE POSITIVE.** Same root cause as above.

**MEDIUM injection finding (borderline):**

`omc-configure-notifications` — `SKILL.md` line 607: "Override the default"  
This is Slack notification documentation explaining `<!channel>` vs `<!here>` mention
formats. The injection rule fires on "Override" in a context that is obviously
documentation about Slack API behavior, not an instruction-override attack.  
Verdict: **FALSE POSITIVE** (injection rule's priority-override pattern is over-broad
for common English phrases in documentation). Not addressed in this tuning pass
(the injection rule has its own precision profile).

---

## Root Cause Analysis

The `exfiltration` rule treated env-var names (`$GITHUB_TOKEN`, `$BITBUCKET_TOKEN`,
`$_API_KEY`) with the same HIGH-severity weight as literal credential-file reads
(`cat ~/.aws/credentials`, `cat ~/.ssh/id_rsa`).

**Pattern causing FP:**
```
SECRET_PATTERNS includes:
  /\b[A-Z][A-Z0-9]*(?:_TOKEN|_SECRET|_API_?KEY|...)\b/
```

This matches any env var that looks like a credential. When the same script also
contains `curl`, the combined HIGH fires — even when the `curl` goes to the official
API endpoint for that token (standard API auth).

**The distinction that matters:**
- Reading `~/.aws/credentials` + sending to any host = credential theft (HIGH)
- Using `$GITHUB_TOKEN` as an auth header to `api.github.com` = normal OAuth (not HIGH)
- Using `$GITHUB_TOKEN` as an auth header to `webhook.site` = exfiltration (HIGH)

---

## Changes Made

### `src/rules/exfiltration.ts` — Secret tier split

Introduced `SECRET_CREDENTIAL_PATTERNS` (tier 1) and `SECRET_ENV_PATTERNS` (tier 2).
`SECRET_PATTERNS` = union (backward-compat).

**New per-unit severity contract:**

| Secret tier | Egress | Severity |
|-------------|--------|----------|
| Tier 1 (file/literal) | Any (curl, fetch, etc.) | HIGH |
| Tier 1 (file/literal) | Suspicious host | HIGH |
| Any | Suspicious host (webhook.site, ngrok, etc.) | HIGH |
| Tier 2 (env var name) | Non-suspicious egress | MEDIUM (was HIGH) |
| Tier 1 (file/literal) | None | MEDIUM |
| Tier 2 (env var name) | None | LOW |

### `src/rules/crossUnitTaint.ts` — EXF-CORR MEDIUM tier tightened

The MEDIUM cross-unit finding (isolated secret + literal external URL in another
file) now requires a **tier-1 file secret** in the secret-bearing unit.

A multi-file skill that exports `$SERVICE_API_KEY` in one script and calls
`curl https://api.service.com` in another now receives **LOW** instead of **MEDIUM**
from EXF-CORR. The EXF-CORR signal still exists (worth review), but MEDIUM is
reserved for genuine credential-file cross-unit taint.

**New EXF-CORR severity contract:**

| Secret tier | Egress target | Severity |
|-------------|--------------|---------|
| Any | Suspicious host (across units) | HIGH |
| Tier 1 (file/literal) | Literal external URL (across units) | MEDIUM |
| Tier 2 (env var) | Literal external URL (across units) | LOW (was MEDIUM) |
| Any | Variable URL / generic egress | LOW |

---

## Results After Tuning

### `~/.claude/skills` (45 skills)

| Rule | HIGH | MEDIUM | LOW |
|------|------|--------|-----|
| malicious-code | 0 | 1 | 0 |
| **Total** | **0** | **1** | **0** |

No change (these skills never had HIGH findings from the affected rules).

### Plugin OMC skills (~50 skills)

| Rule | HIGH | MEDIUM | LOW |
|------|------|--------|-----|
| exfiltration | **0** (was 2) | **2** (was 0) | 0 |
| injection | 0 | 1 | 0 |
| **Total** | **0** | **3** | **0** |

The 2 HIGH FPs (bitbucket.sh, gitea.sh) are now correctly at MEDIUM.

### Malicious corpus (28 fixtures)

**Recall: 28/28 — unchanged.**

All 28 malicious exfiltration fixtures use tier-1 secrets:
- `exfil-creds`, `base64-exfil`, `email-exfil`, `aws-metadata`, `split-exfil`:
  read `~/.aws/credentials` (tier 1) → still HIGH
- `cookie-stealer`: reads `cookies.sqlite` (tier 1) → still HIGH
- `dns-exfil`: reads `~/.ssh/id_rsa` (tier 1) → still HIGH
- `gcp-metadata`: reads `metadata.google.internal` IMDS (tier 1) → still HIGH

None of the malicious fixtures use env-var names like `$GITHUB_TOKEN`. The tier
split does not affect recall.

---

## False Positive Rate (HIGH)

| Corpus | Before | After |
|--------|--------|-------|
| `~/.claude/skills` (45 skills) | 0 HIGH FPs | 0 HIGH FPs |
| Plugin OMC skills (~50 skills) | 2 HIGH FPs | 0 HIGH FPs |
| **Combined HIGH FP count** | **2** | **0** |

**HIGH FP rate: 0% (after tuning)**

---

## Residual MEDIUM / LOW Profile

After tuning, MEDIUM findings on benign skills are:

| Skill | Rule | Finding | Assessment |
|-------|------|---------|------------|
| `webapp-testing` | malicious-code | `subprocess.Popen(cmd, shell=True)` | TRUE CONCERN — shell injection risk |
| `omc-project-session-manager` (bitbucket.sh) | exfiltration | Env token + API egress | Expected MEDIUM — legitimate API auth worth reviewing |
| `omc-project-session-manager` (gitea.sh) | exfiltration | Env token + API egress | Expected MEDIUM — same |
| `omc-configure-notifications` | injection | "Override the default" in docs | FP — injection rule over-broad on common English phrases |

The 3 MEDIUM findings from `omc-project-session-manager` are correct: a skill
scanner should note that these scripts make authenticated API calls. MEDIUM signals
"worth reviewing", not "do not install".

---

## Genuinely Risky Real Skill Discovered

**`webapp-testing` — `scripts/with_server.py`**

```python
process = subprocess.Popen(
    command,
    shell=True,
)
```

`subprocess.Popen(command, shell=True)` where `command` comes from CLI args is a
real shell-injection risk. The webapp-testing skill is a test-runner helper and in
context the command is expected to come from trusted developer input, but the
pattern is dangerous if the skill were used with untrusted input or composed with
another skill that passes user-controlled data.

**Recommendation:** Surface this MEDIUM to the user. It is an accurate finding.

---

## New Artifacts

| File | Purpose |
|------|---------|
| `src/rules/exfiltration.ts` | Two-tier `SECRET_CREDENTIAL_PATTERNS` / `SECRET_ENV_PATTERNS` split |
| `src/rules/crossUnitTaint.ts` | EXF-CORR MEDIUM tightened to require tier-1 file secret |
| `test/rules.test.ts` | +5 new unit tests covering the FP fix and EXF-CORR tightening |
| `test/fixtures/benign-real/` | 5 sanitized real-skill fixture directories |
| `test/precision.test.ts` | Hermetic precision gate: 0 HIGH on benign-real corpus |
| `PRECISION_REPORT.md` | This report |
| `README.md` | Precision posture section updated |
| `CHANGELOG.md` | Precision audit entry added |
