#!/usr/bin/env python3
"""Generate the 2-page Track 4 project brief PDF (brief + threat model).

Output: Track4_Brief.pdf at the repository root. Re-run any time the docs
change. The demo-video line is filled from DEMO_VIDEO_LINK env var or left
as an explicit TODO marker.
"""

import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "Track4_Brief.pdf")
VIDEO = os.environ.get("DEMO_VIDEO_LINK",
                       "TODO: paste the public (unlisted) video link here")

ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=16, spaceAfter=4)
H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=12, spaceBefore=8,
                    spaceAfter=3, textColor=colors.HexColor("#1a3d6d"))
BODY = ParagraphStyle("BODY", parent=ss["BodyText"], fontSize=8.6, leading=11)
CELL = ParagraphStyle("CELL", parent=BODY, fontSize=7.6, leading=9.4)
CELLH = ParagraphStyle("CELLH", parent=CELL, fontName="Helvetica-Bold")

sm = ParagraphStyle("Code", parent=ss["BodyText"],
                    fontName="Courier", fontSize=7, leading=9)


def P(t, s=BODY):
    return Paragraph(t, s)


def checklist_table():
    rows = [
        [P("Objective", CELLH), P("Implementation & verified result", CELLH)],
        [P("1. Key rotation", CELL),
         P("New ML-KEM-768 version per rotation; old version honored until a "
           "documented cutoff (grace 30 s simulated time); every node rejects "
           "old keys after cutoff; authorized transfers continue in-window.", CELL)],
        [P("2. Revocation across nodes", CELL),
         P("Per-node enforcement at revoked_at + sync_delay (node-a 0 s, "
           "node-b 2 s); time until last node enforces is reported (2.0 s); "
           "owner re-enrols, other users retain access.", CELL)],
        [P("3. Crash recovery", CELL),
         P("Rotations journaled before commit; recovery replays to last "
           "commit marker; revocations persist; data stays available; total "
           "disk loss falls back to signed backups (reported honestly).", CELL)],
        [P("4. Backup integrity", CELL),
         P("ML-DSA-signed manifest over SHA-256 payload, stored outside the "
           "live state; signature+hash verified before anything loads; "
           "damaged backups reported and refused.", CELL)],
        [P("5. Log integrity", CELL),
         P("Every entry hash-chained and ML-DSA-signed; user text only in a "
           "single JSON field (injection-proof); verify_log reports first "
           "bad entry and reason.", CELL)],
        [P("6. Routine vs suspicious", CELL),
         P("Explainable rules over labelled logs: F1 = 1.0, median "
           "time-to-alert 1.2 s, 0 false alerts per 1,000 benign events.", CELL)],
        [P("7. Lateral movement", CELL),
         P("Bursts of >=2 unknown service edges flagged even with valid "
           "credentials; each alert names identity, services, events, "
           "rule/path (e.g. reports->billing->archive->identity).", CELL)],
        [P("8. Clock differences", CELL),
         P("Offsets up to +/-60 s normalized to true time; arrival "
           "inversions within 10 s annotated; beyond that flagged "
           "order_uncertain.", CELL)],
        [P("9. Replay + recipient binding", CELL),
         P("AES-GCM AAD binds (session, sender, recipient, counter); "
           "duplicates and modified bindings rejected.", CELL)],
        [P("10. Forward secrecy", CELL),
         P("Session key from a fresh ephemeral ML-KEM keypair, zeroized at "
           "accept; session key zeroized at close; later long-term-key "
           "exposure cannot reveal completed sessions.", CELL)],
        [P("11. Delivery under loss/reordering", CELL),
         P("In-order delivery across gaps <= 8; failures reported; invalid "
           "messages discarded.", CELL)],
        [P("12. Session resumption", CELL),
         P("HMAC(resumption_secret, peer) required; key ratchets per resume; "
           "same sid + different identity rejected.", CELL)],
    ]
    t = Table(rows, colWidths=[42 * mm, 128 * mm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9db3c8")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbe7f3")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


story = [
    P("Track 4 &mdash; &quot;Trust, but verify&quot;: Post-Quantum Key "
      "Lifecycle, Identity and Access Control", H1),
    P("All cryptography from vetted libraries only: ML-KEM-768 (FIPS 203), "
      "ML-DSA-65 (FIPS 204) via <b>pqcrypto</b>; HKDF-SHA256 and AES-256-GCM "
      "via <b>cryptography</b>. No custom primitives, no AI/ML, no "
      "hard-coded secrets. Verified by 23 objective tests plus the "
      "organizer's lost-device validator (all checks PASS)."),
    Spacer(1, 2 * mm),
    P("USP: Recovery-first key lifecycle with evidence you can check", H2),
    P("Every disruptive event &mdash; rotation, revocation, crash, damaged "
      "backup, tampered log, stolen device &mdash; is not only handled but "
      "<b>measured and reported</b>: the time until the last node enforces a "
      "revocation, the exact committed key version after a crash, the reason "
      "and position of the first bad audit entry, and F1 / median "
      "time-to-alert / false-alerts-per-1000 for the detector on labelled "
      "logs. Operators don't have to trust the prototype; the prototype "
      "reports why it should be trusted."),
    P("System architecture", H2),
    P("track4_service.py (JSON stdin/stdout) &rarr; src/dispatch.py (op "
      "registry) &rarr; domain modules: keys (rotation/cutoff/revocation), "
      "access (identity decisions), recovery (journal replay, signed "
      "backups), messaging (ephemeral-KEM E2E sessions), audit (hash-chained "
      "signed log), detector (explainable rules + metrics), state (atomic "
      "writes + durable fsync journal + simulated clock). Every mutating op "
      "appends a signed audit entry; every decision carries explicit reasons.", BODY),
    P("Objective checklist &rarr; implementation and measured result", H2),
    checklist_table(),
    PageBreak(),
    P("Performance &amp; overhead", H2),
    P("23-test objective suite runs end-to-end in ~1.4 s. Per-session "
      "ML-KEM-768 keygen+encaps+decaps ~1 ms; ML-DSA-65 sign/verify per "
      "audit entry ~1 ms, so per-entry signing keeps log overhead low. "
      "Detector over the 22-event labelled log: &lt; 5 ms, deterministic. "
      "Operational overhead is dominated by per-entry ML-DSA signatures and "
      "an fsync per journal record &mdash; both bounded and documented."),
    P("One-page threat model", H2),
    P("<b>Protected assets:</b> (1) E2E-protected messages "
      "(confidentiality, integrity, freshness, recipient binding); (2) key "
      "material: service ML-DSA key, ML-KEM key versions, ephemeral session "
      "secrets, session and resumption keys; (3) access-control state "
      "(owners, roles, disabled actors, revoked devices, epochs); (4) audit "
      "log integrity and non-repudiation; (5) backup integrity and "
      "availability; (6) the operator's alert view."),
    P("<b>Attackers considered:</b> malicious client with valid credentials "
      "(scope violations, session theft, replay, log injection); insider "
      "privilege escalator (unapproved role changes); service-account abuser "
      "traversing unusual service paths; network attacker (drop, reorder, "
      "replay, modify); local file attacker (state/journal/backup tampering "
      "&mdash; met by atomic writes, signed backups, signed hash-chained "
      "log); later compromise of a long-term identity key (met by ephemeral "
      "per-session KEM keys, zeroized); stolen device (revocation with "
      "measured propagation, owner re-enrolment)."),
    P("<b>Assumptions:</b> the host process is not compromised while running "
      "(on-disk tampering is in scope, memory disclosure is not); "
      "approvals.json is an authentic authorization source; the service "
      "ML-DSA key is generated at setup and never journaled; the simulated "
      "clock and two-node delays faithfully model propagation; backup "
      "storage is access-controlled (backups are signed, not encrypted)."),
    P("<b>Limits (honest):</b> both messaging endpoints share one process in "
      "the prototype; resumption-secret exposure breaks future resumption "
      "of that session only; the detector's service graph and role scopes "
      "are explicit, documented constants (fail-closed); the audit log is "
      "unbounded (segment sealing is future work); DoS and traffic analysis "
      "are out of scope; no attacks against other teams or shared services."),
    P("Verification &amp; reproduction", H2),
    P("python3 -m venv .venv &amp;&amp; source .venv/bin/activate; pip "
      "install -r requirements.txt; python3 -m unittest discover -s tests "
      "(23 tests); python3 demo.py (45-step scripted walkthrough printing "
      "every checkpoint).", sm),
    Spacer(1, 2 * mm),
    P("<b>5-minute demo video:</b> %s" % VIDEO),
    P("Repository: created during the hackathon; full source under src/ with "
      "tests/, docs/ (this brief + threat model), README with clean-machine "
      "setup steps.", BODY),
]

doc = SimpleDocTemplate(OUT, pagesize=A4,
                        leftMargin=15 * mm, rightMargin=15 * mm,
                        topMargin=12 * mm, bottomMargin=12 * mm,
                        title="Track 4 Project Brief",
                        author="Track 4 team")
doc.build(story)
print("wrote", OUT)
