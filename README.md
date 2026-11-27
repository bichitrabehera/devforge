# DevForge — Trust, but verify

Track 4 prototype: a post-quantum key-lifecycle and access-control engine with
tamper-evident audit, recovery and explainable detection.

- **Team:** Powerhouse
- **Leader:** Bichitra Behera
- **Repository:** https://github.com/bichitrabehera/devforge

## 1. Setup this repository (main engine)

The engine is the required deliverable. It needs only Python and two packages.
No Node.js, FastAPI, database, API keys or organizer services are needed here.

### Requirements

- Python 3.12
- `git` and `pip`

### Install

```bash
git clone https://github.com/bichitrabehera/devforge.git
cd devforge

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` contains only `pqcrypto` and `cryptography`.

### Choose a state directory

```bash
export TRACK4_STATE_DIR="$PWD/.track4_state"
mkdir -p "$TRACK4_STATE_DIR"
```

If unset, the engine uses `/tmp/track4_state`.

### Run the engine

`track4_service.py` takes one JSON request on stdin and returns one JSON
response on stdout.

```bash
echo '{"op": "setup", "grace_seconds": 30.0}' | python3 track4_service.py
echo '{"op": "status"}' | python3 track4_service.py
echo '{"op": "demo"}' | python3 track4_service.py
```

`{"op":"demo"}` runs the full engine walkthrough: rotation, revocation,
recovery, backup/log integrity, messaging and detection.

### Verify

```bash
python3 -m unittest discover -s tests -v
python3 demo.py
```

Detailed evidence lives in `docs/EVIDENCE_MATRIX.md`,
`docs/DETECTOR_METRICS.md`, `docs/THREAT_MODEL.md` and
`docs/PROJECT_BRIEF.md`.

## 2. Optional: run it live with the operator console

Skip this section if you only need the engine. The FastAPI backend and Next.js
console are thin layers over the same engine; they let you click through the
scenario instead of sending JSON by hand.

### Backend

```bash
# From the repository root, with the engine venv active:
python3 -m pip install -r server/requirements.txt

cd server
uvicorn main:app --reload --port 8000
```

Health check: `http://localhost:8000/health`.

### Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`. `frontend/.env.local` points to the API on port
8000. Use **Run next** in the right column, or click the active step chips, to
walk through sessions, messaging, revocation, recovery, resilience checks and
detection. If the banner says `device-blair is revoked`, click **Reset demo
state** first.
