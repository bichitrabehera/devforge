Track 4: "Trust, but verify"

Domain: Post-quantum cryptography, identity and access control
Environment: Organizer sandbox with mock services, synthetic access logs and test identities

1. Mission Brief
Build one working prototype that protects messages or files as keys, devices and user permissions change. Use its access logs to show an operator when an identity gains unexpected privileges or starts accessing other services.

2. Core Challenge Objectives
Use these goals as a checklist for your Track 4 prototype.


Key rotation. Authorized transfers continue during rotation. Every node rejects new requests that use the old key after the documented cutoff. State whether a grace period applies.
Revocation across nodes. Every node rejects a revoked key. Report the time from revocation until the last node enforces it. After device loss, its owner can re-enrol and other users retain access.
Crash recovery. After an interrupted rotation, the service recovers a consistent, authorized key version. Previously revoked keys stay revoked, and committed keys and protected data remain available.
Backup integrity. Recovery detects a damaged key backup and reports the failure. The service uses only verified key material.
Log integrity. Each event keeps its original identity, action and record boundary. User-supplied text cannot create an apparent second event or change the recorded actor. Operators can verify the integrity of the key-event log.
Routine and suspicious activity. The detector uses context to distinguish approved administration from suspicious privilege changes or data access. Report F1, median time to alert and false alerts per 1,000 benign events on labelled logs.
Lateral movement. The detector flags unusual access paths between services even when the credentials are valid. Each alert identifies the identity, services, events and rule or path that explains it.
Clock differences. The detector handles events that arrive out of order or carry different clock offsets. State the supported timing range and flag cases where event order is uncertain.
Replay and recipient binding. Only the intended recipient can read an end-to-end encrypted message. The receiver rejects duplicate messages and messages whose authenticated recipient information has changed.
Forward secrecy. Later exposure of a long-term identity key alone does not reveal the contents of earlier, completed sessions.
Delivery under loss or reordering. The receiver delivers complete, authenticated messages when recovery succeeds. It discards incomplete or invalid messages and reports delivery failures.
Session resumption. If supported, a resumed session remains bound to its authenticated peer. A different identity cannot inherit the session by presenting the same session identifier.
3. Deliverables & System Architecture
Your final submission must cover the following components:


Working Prototype: Demonstrate the protected workflow in the organizer sandbox.
Source & Setup (Public GitHub Repository): Submit the repository, dependency list, and a README.md with clean-machine setup steps.
2-Page Project Brief (PDF): Include your USP and system architecture alongside:
One-Page Threat Model: Identify protected assets, possible attackers, assumptions, and limits.
5-Minute Demo Video Link: Embed a publicly accessible link (e.g., unlisted YouTube or Google Drive) to a 5-minute walkthrough recording inside the PDF as a fallback if the live demo fails.
Submission Format
Public GitHub Repository URL: Created during the hackathon with full source code and clean-machine setup instructions.
2-Page Project Brief (PDF): Contains your USP/architecture overview, your 1-page threat model, and the link to your 5-minute demo video.
4. Prerequisites & Recommended Libraries
Post-Quantum Cryptography: Use a vetted library that implements the standardized algorithm your design needs. ML-KEM establishes a shared secret. ML-DSA and SLH-DSA provide digital signatures. A hybrid design can combine classical and post-quantum algorithms.
Identity Controls: Be ready to explain how your prototype checks an identity, applies permissions and records its decision.
Detection: Use explainable rules, statistics or graph-based methods. Document the dependencies used by your prototype.
5. Evaluation & Scoring
Stage 1 — Automated Build & Assessment (100 Points)
Organizers build the submitted repository in a clean sandbox and run automated functional and security verification tests to advance the Top 10 teams to the desk review:


Criteria

Points

Description

Security Correctness

25 points

Evaluation of fundamental cryptographic and identity security implementations.

Live / Automated Security Assessment

25 points

Starts at 25 points. Each confirmed critical, high, medium, or low finding deducts 10, 6, 3, or 1 point respectively. Detecting and responding during the assessment restores up to half the deduction; minimum score is 0.

Functionality & Reliability

20 points

5 points each for normal operation, security controls, recovery after disruption, and verifiable outcomes. Use the checklist examples to demonstrate these behaviors.

Threat Model & Honesty

10 points

Assessment of threat model completeness, asset identification, and constraint awareness.

Performance & Overhead

10 points

System efficiency, latency metrics, and operational overhead evaluation.

Usability & Documentation

10 points

Code cleanliness, README clarity, and setup repeatability on a clean machine.

Stage 2 — Desk Review & Round 3 Finals
The Top 10 teams undergo a live desk review featuring a 5-minute demo, 5 minutes of technical questions, and a live security assessment in the sandbox to select the Top 2 finalists for Round 3 final judging.

6. Ground Rules
Scope: Use only the assigned sandbox, mock services and test identities. Attacks on other teams or out-of-scope systems are grounds for disqualification. Denial-of-service against shared services is prohibited.
Submission Integrity: Hard-coded secrets, AI/ML components, custom cryptographic primitives presented as secure, and plagiarism without attribution are grounds for disqualification.
Original Work: Your repository must be created during the hackathon. Pre-existing open-source libraries are permitted, provided your core prototype and security controls are built during the event.
