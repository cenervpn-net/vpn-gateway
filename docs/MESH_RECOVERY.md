# Mesh Peer Recovery System

## Overview

The Mesh Peer Recovery System is a distributed, zero-knowledge architecture that enables automatic restoration of VPN peer configurations after gateway reprovisioning. This document describes the system's design, operation, and troubleshooting.

---

## Design Principles

### Zero-Knowledge Architecture

The backend and mesh nodes **never** see plaintext peer configurations:

1. **Gateway encrypts** peer configs using a key derived from its WireGuard private key
2. **Encrypted blobs** are broadcast to all mesh nodes
3. **Only the owning gateway** can decrypt its own blobs
4. Backend stores blobs but cannot read their contents

### Distributed Storage

Peer configurations are replicated across multiple storage layers:

```
                    ┌─────────────────┐
                    │ Backend Mesh 1  │──┐
                    └─────────────────┘  │
                                         ├── 2x Replication
                    ┌─────────────────┐  │
                    │ Backend Mesh 2  │──┘
                    └─────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Gateway 1  │     │  Gateway 2  │     │  Gateway N  │
│ (RAM cache) │     │ (RAM cache) │     │ (RAM cache) │
└─────────────┘     └─────────────┘     └─────────────┘
```

### Self-Healing

The system automatically handles:
- Gateway crashes and restarts
- Network partitions
- Node additions and removals
- Stale data cleanup

---

## Data Structures

### Encrypted Blob

```json
{
  "encrypted_payload": "base64_encoded_ciphertext",
  "nonce": "12_byte_iv_base64",
  "peer_id_hash": "sha256_of_pubkey_first_16_chars",
  "status": "active|suspended",
  "timestamp": "2026-01-14T10:30:00Z"
}
```

### Storage Entry

```json
{
  "identity": "full_gateway_pubkey",
  "stored_at": "2026-01-14T10:30:00Z",
  "blobs": [
    { "encrypted_payload": "...", "peer_id_hash": "...", "status": "active" },
    { "encrypted_payload": "...", "peer_id_hash": "...", "status": "active" }
  ]
}
```

### Identity Hash

Each gateway is uniquely identified by a hash of its WireGuard public key:

```python
import hashlib

wg_public_key = "0cvSmxPgoSIb6BKN5vu9fe8tQzTBo4WgjPVEcgq2czc="
identity_hash = hashlib.sha256(wg_public_key.encode()).hexdigest()[:16]
# Result: "d564e8b81e63d43d"
```

---

## Operations

### Peer Creation Flow

```
1. Client creates peer via API
   └─► POST /api/v1/configurations/

2. Gateway creates WireGuard peer
   └─► wg set wg0 peer <pubkey> ...

3. Gateway encrypts peer config
   └─► AES-256-GCM with derived key

4. Gateway broadcasts to mesh
   └─► POST /whisper/peer-data/store (to all nodes)

5. Mesh nodes store blob
   └─► Indexed by gateway identity_hash
```

### Gateway Recovery Flow

```
1. Gateway starts up
   └─► whisper_node.py startup

2. Gateway identifies itself
   └─► Derives identity from WG private key

3. Gateway queries mesh for its blobs
   └─► POST /whisper/peer-data/retrieve

4. Gateway decrypts and restores peers
   └─► Recreates WG peers from configs

5. If mesh empty, fallback to WG scan
   └─► Scan local WG interfaces for existing peers
```

### Periodic Sync (Every 10 minutes)

```
1. Gateway initiates sync
   └─► POST /whisper/mesh/sync (to backend mesh)

2. Receives all blobs for its identity
   └─► Updates local cache

3. Detects missing/new blobs
   └─► Logs discrepancies

4. Reports sync status
   └─► recovery_events updated
```

---

## Encryption Details

### Key Derivation

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Derive encryption key from WG private key
wg_private_key = load_wg_private_keys()[0]  # Base64 string
key_bytes = base64.b64decode(wg_private_key)

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"mesh_peer_recovery",
    info=b"peer_config_encryption"
)
derived_key = hkdf.derive(key_bytes)
```

### Encryption

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aesgcm = AESGCM(derived_key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, plaintext_config.encode(), None)
```

### Decryption

```python
plaintext = aesgcm.decrypt(nonce, ciphertext, None)
config = json.loads(plaintext.decode())
```

---

## API Reference

### Store Peer Blob

```http
POST /whisper/peer-data/store
Content-Type: application/json

{
  "identity": "gateway_pubkey",
  "encrypted_payload": "base64_ciphertext",
  "nonce": "base64_nonce",
  "peer_id_hash": "abcd1234...",
  "status": "active",
  "timestamp": "2026-01-14T10:30:00Z"
}
```

### Retrieve Peer Blobs

```http
POST /whisper/peer-data/retrieve
Content-Type: application/json

{
  "identity": "gateway_pubkey",
  "timestamp": "2026-01-14T10:30:00Z",
  "nonce": "random_string"
}
```

Response:
```json
{
  "blobs": [
    {
      "encrypted_payload": "...",
      "nonce": "...",
      "peer_id_hash": "...",
      "status": "active"
    }
  ],
  "total": 2
}
```

### Get Storage Stats

```http
GET /whisper/peer-data/stats
```

Response:
```json
{
  "total_identities": 4,
  "total_blobs": 15,
  "own_identity": "0cvSmxPgoSIb...",
  "own_identity_hash": "d564e8b81e63d43d",
  "own_blobs": 3,
  "own_by_status": {
    "active": 3,
    "suspended": 0
  },
  "storage_summary": [
    {
      "identity_hash": "d564e8b81e63d43d",
      "blob_count": 3,
      "is_own": true
    }
  ]
}
```

---

## Orphan Detection

### What is an Orphan?

An orphaned blob is one whose owning gateway:
- Has been deleted from the system
- Has been reprovisioned with a new identity
- Is no longer active

### Detection Algorithm

```python
# Backend mesh status check
active_identities = {}
for gateway in active_gateways:
    stats = fetch_gateway_stats(gateway)
    identity_hash = stats["own_identity_hash"]
    active_identities[identity_hash] = gateway.name

# Check each stored identity
for identity_hash in mesh_storage:
    if identity_hash not in active_identities:
        mark_as_orphan(identity_hash)
```

### Auto-Purge

Orphaned blobs are automatically purged after 7 days:

```python
ORPHAN_AUTO_PURGE_DAYS = 7

if orphan_age_days >= ORPHAN_AUTO_PURGE_DAYS:
    purge_identity(identity_hash)
```

### Manual Purge

```http
POST /api/admin/mesh/purge-orphans
```

---

## Troubleshooting

### Blobs Not Being Stored

**Symptoms:** `own_blobs = 0` after creating peers

**Checks:**
```bash
# Verify mesh connectivity
curl -sk https://localhost:8100/status | jq '.alive_peers'

# Check broadcast logs
sudo journalctl -u whisper-node | grep -i broadcast

# Verify backend mesh is reachable
curl -s http://127.0.0.1:8101/status
```

### Recovery Failing

**Symptoms:** Peers not restored after restart

**Checks:**
```bash
# Check identity consistency
curl -sk https://localhost:8100/whisper/peer-data/stats | jq '.own_identity_hash'

# Check if blobs exist for this identity
curl -s http://127.0.0.1:8101/whisper/peer-data/stats | jq '.storage_summary'

# Check WireGuard private key path
cat /etc/amnezia/amneziawg/*.conf | grep PrivateKey
```

### All Blobs Showing as Orphaned

**Symptoms:** Dashboard shows valid peers as orphans

**Root Cause:** Identity hash mismatch between gateway stats and mesh storage

**Fix (v1.3.0):** Gateway now returns `own_identity_hash` pre-computed

```bash
# Verify gateway returns correct hash
curl -sk https://localhost:8100/whisper/peer-data/stats | jq '{
  own_identity_hash: .own_identity_hash,
  storage_hashes: [.storage_summary[].identity_hash]
}'

# own_identity_hash should match one of the storage_hashes
```

---

## Configuration

### Timing Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `HEARTBEAT_INTERVAL` | 10s | How often to send heartbeats |
| `PERIODIC_MESH_SYNC_INTERVAL` | 600s | Full sync frequency |
| `MAX_BROADCAST_RETRIES` | 3 | Retry count for blob broadcast |
| `BROADCAST_RETRY_DELAY_SECONDS` | 1s | Base delay between retries |
| `ORPHAN_DETECTION_INTERVAL` | 86400s | Orphan scan frequency |
| `ORPHAN_AUTO_PURGE_DAYS` | 7 | Days before auto-purge |

### Mesh Addresses

Configure mesh peer addresses in `.env`:

```bash
# Other gateway whisper nodes
MESH_PEER_ADDRESSES=10.100.0.100:8100,10.100.0.101:8100,10.100.0.102:8100

# Backend mesh nodes
BACKEND_MESH_ADDRESSES=127.0.0.1:8101,127.0.0.1:8102
```

---

## Security Considerations

1. **Private Key Protection**: WireGuard private key is used for key derivation - protect at all costs
2. **Blob Integrity**: Each blob is authenticated with AES-GCM - tampering is detected
3. **Identity Spoofing**: Only the gateway with the correct private key can claim an identity
4. **Network Security**: All mesh communication uses mTLS

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.3.0 | 2026-01-14 | Fixed identity hash matching in orphan detection |
| 1.2.0 | 2026-01-13 | Added periodic sync and broadcast retry |
| 1.1.0 | 2026-01-11 | WireGuard fallback recovery |
| 1.0.0 | 2026-01-10 | Initial release |
