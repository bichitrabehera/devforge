# Hackathon Track 4 - Clean Machine Setup

## Python 3.12 + pqcrypto Setup

```bash
# Create a clean virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install required packages
pip install pqcrypto cryptography

# Verify installations
python3 -c "import pqcrypto; print('pqcrypto:', pqcrypto.__version__)"
python3 -c "from cryptography.hazmat.primitives.kdf.hkdf import HKDF; print('cryptography OK')"

# Set up state directory
export TRACK4_STATE_DIR=/tmp/track4_state
# Or for persistent state:
# export TRACK4_STATE_DIR=$HOME/track4_state

# Create required directories
mkdir -p $TRACK4_STATE_DIR/track4_backups

# Verify the service works
python3 -c "
import json, sys
sys.path.insert(0, '.')
from team_app import dispatch

# Test setup op
result = dispatch({'op': 'setup'})
print('Setup OK:', result['status'])

# Test read op
result = dispatch({'op': 'read'})
print('Read OK:', result['status'])
"
```

## Project Structure

```
.
├── team_app.py        # Core engine (dispatch + 11 helpers)
├── track4_service.py  # STDIN/JSON adapter entry point
├── detector.py        # Anomaly & lateral-movement analyzer
├── threat-model.json  # Asset: protected-resource, Boundary: identity-check
├── evidence-sheet.md  # 12 goals + measurement record
├── events.csv         # 22 synthetic events
├── approvals.json     # Authorized change scope and validity
└── README.md          # This file
```

## Running the Service

```bash
# Read JSON from stdin, dispatch, write JSON to stdout
echo '{"op": "setup"}' | python3 track4_service.py

# Full test cycle
python3 -c "
import json, sys
sys.path.insert(0, '.')
from team_app import *

# Open session
r = open_session({'user_id': 'alice'})
sid = r['session_id']

# Send encrypted message
s = send_message({'to_session_id': sid, 'msg': 'hello'})
ct = s['ct']

# Receive encrypted message
r = receive_message({'from_session_id': sid, 'ct': ct})
print('Decrypted:', r['msg'])
"
```
