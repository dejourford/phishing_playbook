# Phishing Incident Response Playbook (SOC/CSIRT)

**Audience:** Tier 1–3 Analysts, Incident Handlers, IR Lead
**Scope:** Email‑borne phishing (credential harvest, malware delivery, BEC/finance lures) across corporate mail and collaboration systems.

---

## 1) Purpose & Definition

**Purpose.** Provide a clear, repeatable path to handle user‑reported or tool‑detected phishing, from first report through lessons learned.
**Phishing (definition).** Social engineering delivered via email (and related channels) where an adversary impersonates a trusted sender to trick a user into clicking links, opening attachments, or revealing secrets.

---

## 2) Objectives

* Rapidly detect and triage suspected phish.
* Limit business impact (prevent credential theft, malware execution, or wire fraud).
* Capture indicators/telemetry to improve detections and training.
* Feed lessons back into controls, playbooks, and awareness.

---

## 3) Roles at a Glance

* **Analyst (T1/T2):** Triage, artifact collection, scope, initial containment.
* **Incident Handler / IR Lead:** Severity call, coordination, comms, approval for destructive actions.
* **Messaging/Identity SMEs:** Mail purge, transport rules, account reset, token revocation.
* **Endpoint SME/EDR:** Host isolation, scans, artifact retrieval.
* **Comms/Leadership:** User notifications, stakeholder updates.

---

## 4) Triggers

* User report (e.g., Phish‑Alert button) → ticket + SIEM event.
* Security alerts (email security, TI hits, anomaly detections).
* External notifications (partners/ISACs).

---

## 5) Workflow Overview (SANS‑style)

**Prepare → Identify → Contain → Eradicate → Recover → Post‑Incident Improvement**

---

## 6) Preparation (what must be in place)

* **User reporting:** One‑click report button in mail client; route to shared mailbox/ticket + SIEM queue.
* **Email defenses:** Modern email security (sandbox/URL rewrite/attachment detonation) in block for high‑confidence threats; enforce SPF/DKIM/DMARC; domain‑lookalike protections.
* **Logging:** Unified audit/mailbox audit; hunting tables for email events, URL clicks, attachment verdicts; identity sign‑in logs; endpoint EDR telemetry.
* **Runbooks & automation:** Pre‑approved flows to purge mail, block senders/URLs, reset accounts, revoke tokens; logic app/SOAR connectors wired.
* **Awareness:** Simulations and targeted training for clickers.

---

## 7) Identification & Initial Triage (≤10 minutes SLA)

**Collect:**

* Original message (headers, body, URLs, attachments), number of recipients, reported time.

**Quick checks:**

* **Headers:** Auth results (SPF/DKIM/DMARC), sending IP, domain age, display‑name tricks.
* **Content:** Tone/urgency, brand impersonation, payment/payroll/MFA themes, QR codes, HTML smuggling.
* **Reputation:** Hash/URL/domain/IP against internal TI and reputable external sources. Use passive checks first; sandbox only if necessary and policy allows.

**Decide severity:**

* **High:** Evidence of credential capture or malware execution, VIP/BEC themes, many recipients, or sensitive data exposure.
* **Medium:** Suspicious content with clicks but no confirmed submission/execution.
* **Low:** Benign/marketing/simulation.

**Scope quickly:** Determine who received, who clicked, and who executed attachments.

---

## 8) Containment (choose based on evidence)

**Email containment:**

* Tenant‑wide **search & purge** of matching messages; quarantine; update transport rules.
* Add malicious **domains/URLs/senders** to blocklists.

**Identity containment (if credentials may be exposed):**

* **Force password reset**, **revoke refresh tokens**, sign‑out everywhere, enforce/re‑register MFA.
* Watch sign‑ins for impossible travel, unfamiliar locations, risky sign‑ins.

**Endpoint containment (if attachments executed):**

* **Isolate** affected hosts via EDR; kick off on‑demand scans.
* Remove dropped files and start‑up items; capture volatile data when required.

**Network containment:** Short‑TTL blocks for malicious domains/IPs observed in the campaign.

---

## 9) Eradication & Recovery

* Remove mailbox **auto‑forward/redirect rules** and suspicious delegates.
* Fix configuration gaps that allowed delivery (transport exceptions, allow lists).
* Restore clean systems or reimage if integrity is uncertain.
* Validate normal mail flow; monitor closely for recurrence.

---

## 10) Indicators & Intelligence

**Collect & enrich:**

* Sender addresses, sending IPs, reply‑to, domains/URLs, attachment names/hashes (SHA‑256), lure themes, screenshots.
* Store in the org’s TI repository; tag with campaign ID and confidence.
* Create detections/watchlists for recurring patterns (e.g., newly registered domains, brand‑spoof kits).

---

## 11) Communications & Documentation

* Notify impacted users: confirmation of removal, guidance not to re‑open, steps if they interacted.
* Stakeholder update: scope, actions taken, risk, outstanding items, and next steps.
* Ticket hygiene: timeline, artifacts, IOCs, approvals, and residual risk.

---

## 12) Post‑Incident Improvement

* **Hot wash:** What worked, what lagged, where we had false positives/negatives.
* **Detection tuning:** Promote high‑signal analytics; retire noisy ones; add canary tests.
* **Training:** Assign targeted awareness modules to clickers/submitters; adjust simulation difficulty.
* **Policy/Control updates:** Tighten mail and identity policies as needed.

---

## 13) Common ATT\&CK Mappings (use as applicable)

* **TA0001 Initial Access:** T1566 (Phishing) —

  * T1566.001 (Spearphishing Attachment),
  * T1566.002 (Spearphishing Link),
  * T1566.003 (Spearphishing via Service).
* **TA0006 Credential Access:** T1056.007 (Web Forms), T1556 (Modify Authentication Process/MFA abuse) when relevant.
* **TA0002 Execution:** T1204 (User Execution); script/macro execution on endpoints.
* **TA0005 Defense Evasion:** T1564.008 (Email Forwarding Rule), T1027 (Obfuscated/Encoded content).
* **TA0009 Collection / TA0010 Exfiltration:** T1114 (Email Collection); T1041 (Exfiltration Over Web Services/C2) for credential posts.
* **TA0003 Persistence:** T1114.003 (Auto‑forwarding rules) or T1053 (Scheduled Task) if malware established persistence.

---

## 14) Automation Sketch (SIEM/SOAR)

1. **Trigger:** Reported phish or high‑confidence mail security alert → Incident in SIEM.
2. **Enrich:** TI lookup, domain age, detonation verdict (if available).
3. **Decide:** If high‑confidence, auto‑purge and block; else assign to analyst.
4. **Identity:** If any credential post indicators, automatically revoke sessions and enforce password reset.
5. **User comms:** Notify recipients about removal and next steps.
6. **Close‑out:** Write back IOCs, update watchlists, schedule awareness for clickers.

---

## 15) Example Data Points to Pull (for your ticket)

* Delivery timeline (first/last seen), recipient count, click/open metrics.
* URLs/domains (normalized), attachment hashes, detonation verdicts.
* Affected accounts/devices, any admin/mailbox rule changes.
* Actions taken (purge counts, blocks applied, resets, isolates).
* Residual risk and monitoring plan.

---

## 16) Metrics to Track

* **MTTA** (report → triage), **time‑to‑purge**, **click‑through rate**, **submit rate**,
* **False‑positive rate**, and trend of repeat offenders vs. improved cohorts.

---

## 17) Safety Notes

* Prefer passive intel/reputation first; only detonate in an **isolated sandbox** with approved procedures.
* Don’t upload sensitive samples to public services if policy prohibits.

---

### Quick Runbook (1‑page cut‑down for interviews)

1. **Identify:** Pull message + artifacts → headers, content, reputation, severity call.
2. **Contain:** Purge mail; block sender/URL/domain; if creds at risk → reset + revoke; if attachment executed → isolate host and scan.
3. **Eradicate/Recover:** Remove inbox rules, fix configs, restore clean state.
4. **Lessons:** Update detections, train users involved, capture IOCs, brief stakeholders.
