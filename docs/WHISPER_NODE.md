# Whisper Node - Gateway-to-Gateway Communication

## Overview

Whisper Node is the inter-gateway communication layer that enables distributed mesh peer recovery, health monitoring, and coordinated operations across the VPN gateway fleet.

---

## Features

- **mTLS Communication**: Mutual TLS for all inter-gateway traffic
- **Heartbeat Protocol**: Real-time health monitoring
- **Peer Data Replication**: Distributed storage of encrypted peer configs
- **Mesh Synchronization**: Periodic full-mesh sync
- **CRL Enforcement**: Certificate revocation list checking

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Whisper Node                         │
│                                                          │
│  ┌────────────────┐  ┌────────────────┐                │
│  │ Heartbeat      │  │ Peer Data      │                │
│  │ Worker         │  │ Store          │                │
│  │ (10s interval) │  │ (RAM + Disk)   │                │
│  └───────┬────────┘  └───────┬────────┘                │
│          │                   │                          │
│  ┌───────▼───────────────────▼────────┐                │
│  │         FastAPI Application         │                │
│  │         Port 8100 (HTTPS)           │                │
│  └───────────────────┬─────────────────┘                │
│                      │                                   │
│  ┌───────────────────▼─────────────────┐                │
│  │         mTLS Transport               │                │
│  │  - Client cert authentication        │                │
│  │  - CRL verification                  │                │
│  └──────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────┘
```

---

## Endpoints

### Health & Status

#### GET /status
Returns node health and mesh connectivity status.

**Response:**
```json
{
  "status": "healthy",
  "node_id": "node10",
  "known_peers": 5,
  "alive_peers": 4,
  "whisper_version": "1.3.0",
  "uptime": "2d 4h 30m"
}
```

#### GET /whisper/peer-data/stats
Returns detailed storage and mesh statistics.

**Response:**
```json
{
  "total_identities": 4,
  "total_blobs": 12,
  "by_status": {
    "active": 10,
    "suspended": 2,
    "unknown": 0
  },
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
      "stored_at": "2026-01-14T10:30:00Z",
      "statuses": {"active": 3},
      "is_own": true
    }
  ],
  "recent_events": []
}
```

### Peer Data Storage

#### POST /whisper/peer-data/store
Store an encrypted peer configuration blob.

**Request:**
```json
{
  "identity": "full_gateway_public_key",
  "encrypted_payload": "base64_encrypted_data",
  "nonce": "base64_12byte_nonce",
  "peer_id_hash": "sha256_of_peer_pubkey_first16",
  "status": "active",
  "timestamp": "2026-01-14T10:30:00Z"
}
```

**Response:**
```json
{
  "stored": true,
  "message": "Blob stored successfully"
}
```

#### POST /whisper/peer-data/retrieve
Retrieve all blobs for a specific identity.

**Request:**
```json
{
  "identity": "gateway_public_key",
  "timestamp": "2026-01-14T10:30:00Z",
  "nonce": "random_request_nonce"
}
```

**Response:**
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
  "total": 3
}
```

#### DELETE /whisper/peer-data/purge
Purge a specific peer blob.

**Request:**
```json
{
  "identity": "gateway_public_key",
  "peer_id_hash": "hash_of_peer_to_purge"
}
```

#### POST /whisper/purge-identity
Purge all blobs for a given identity hash.

**Request:**
```json
{
  "identity_hash": "d564e8b81e63d43d"
}
```

### Mesh Synchronization

#### POST /whisper/mesh/sync
Request full mesh synchronization.

**Request:**
```json
{
  "requester_pubkey": "requesting_gateway_pubkey",
  "requester_name": "node10",
  "timestamp": "2026-01-14T10:30:00Z",
  "nonce": "random_nonce"
}
```

**Response:**
```json
{
  "success": true,
  "blobs_synced": 12,
  "identities": 4
}
```

### Heartbeat

#### POST /whisper/heartbeat
Gateway heartbeat for health monitoring.

**Request:**
```json
{
  "sender_pubkey": "sending_gateway_pubkey",
  "sender_name": "node10",
  "timestamp": "2026-01-14T10:30:00Z",
  "blob_count": 3,
  "status": "healthy"
}
```

**Response:**
```json
{
  "acknowledged": true,
  "receiver_name": "node15",
  "receiver_blob_count": 2
}
```

---

## Background Workers

### Heartbeat Worker

Sends heartbeats to all known mesh peers every 10 seconds:

```python
HEARTBEAT_INTERVAL = 10  # seconds

def heartbeat_worker():
    while True:
        for peer in mesh_peers:
            try:
                send_heartbeat(peer)
                mark_peer_alive(peer)
            except Exception:
                mark_peer_dead(peer)
        time.sleep(HEARTBEAT_INTERVAL)
```

### Periodic Mesh Sync Worker

Syncs all blobs from backend mesh every 10 minutes:

```python
PERIODIC_MESH_SYNC_INTERVAL = 600  # seconds

def periodic_mesh_sync_worker():
    while True:
        time.sleep(PERIODIC_MESH_SYNC_INTERVAL)
        sync_result = sync_from_mesh()
        log_recovery_event("PERIODIC_MESH_SYNC_COMPLETE", sync_result)
```

---

## Configuration

### Environment Variables

```bash
# Certificates
WHISPER_CERT=/path/to/cert.pem
WHISPER_KEY=/path/to/key.pem
WHISPER_CA=/path/to/ca.crt

# Storage
WHISPER_DATA=/path/to/whisper_data

# Version
WHISPER_VERSION=1.3.0

# Mesh peers
MESH_PEER_ADDRESSES=10.100.0.100:8100,10.100.0.101:8100
BACKEND_MESH_ADDRESSES=127.0.0.1:8101,127.0.0.1:8102
```

### Systemd Service

```ini
[Unit]
Description=Whisper Node - Gateway-to-Gateway Communication
After=network.target wg-manager.service
Wants=wg-manager.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/wg-manager/gateway_api
EnvironmentFile=/home/ubuntu/wg-manager/.env
Environment=WHISPER_CERT=/home/ubuntu/wg-manager/gateway_api/cert.pem
Environment=WHISPER_KEY=/home/ubuntu/wg-manager/gateway_api/key.pem
Environment=WHISPER_CA=/home/ubuntu/wg-manager/gateway_api/ca.crt
Environment=WHISPER_DATA=/home/ubuntu/wg-manager/whisper_data
ExecStart=/home/ubuntu/wg-manager/venv/bin/python whisper_node.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## mTLS Setup

### Certificate Requirements

Each gateway needs:
1. **Server certificate** (`cert.pem`) - Signed by shared CA
2. **Private key** (`key.pem`) - Corresponding to certificate
3. **CA certificate** (`ca.crt`) - For verifying peer certificates

### Certificate Verification

```python
# Server-side (verify client)
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(CERT_PATH, KEY_PATH)
ssl_context.load_verify_locations(CA_PATH)
ssl_context.verify_mode = ssl.CERT_REQUIRED

# Client-side (verify server)
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_cert_chain(CERT_PATH, KEY_PATH)
ssl_context.load_verify_locations(CA_PATH)
```

### CRL Enforcement

Certificate Revocation List is checked before accepting connections:

```python
def verify_certificate_not_revoked(cert_serial: str) -> bool:
    crl = load_crl()
    return cert_serial not in crl.revoked_serials
```

---

## Data Persistence

### RAM Storage (Fast)

Primary storage is in-memory for speed:

```python
peer_recovery_store = {}  # identity -> {blobs, stored_at}
```

### Disk Backup

Periodically persisted to disk for crash recovery:

```python
WHISPER_DATA = os.environ.get("WHISPER_DATA", "/home/ubuntu/wg-manager/whisper_data")

def save_to_disk():
    with open(f"{WHISPER_DATA}/peer_store.json", "w") as f:
        json.dump(peer_recovery_store, f)

def load_from_disk():
    try:
        with open(f"{WHISPER_DATA}/peer_store.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
```

---

## Broadcast Retry Logic

When broadcasting peer data, retries with exponential backoff:

```python
MAX_BROADCAST_RETRIES = 3
BROADCAST_RETRY_DELAY_SECONDS = 1

async def broadcast_with_retry(peer_address, payload):
    for attempt in range(MAX_BROADCAST_RETRIES):
        try:
            response = await send_to_peer(peer_address, payload)
            if response.status_code == 200:
                return True
        except Exception as e:
            logger.warning(f"Broadcast attempt {attempt + 1} failed: {e}")
        
        if attempt < MAX_BROADCAST_RETRIES - 1:
            delay = BROADCAST_RETRY_DELAY_SECONDS * (2 ** attempt)
            await asyncio.sleep(delay)
    
    return False
```

---

## Troubleshooting

### Node Not Receiving Heartbeats

```bash
# Check if mTLS is working
openssl s_client -connect peer_ip:8100 \
  -cert cert.pem -key key.pem -CAfile ca.crt

# Check peer list
curl -sk https://localhost:8100/status | jq '.known_peers, .alive_peers'
```

### Blobs Not Syncing

```bash
# Check backend mesh connectivity
curl -s http://127.0.0.1:8101/status

# Force manual sync
curl -sk -X POST https://localhost:8100/whisper/mesh/sync \
  -H "Content-Type: application/json" \
  -d '{"requester_pubkey":"test","requester_name":"manual","timestamp":"2026-01-14T00:00:00Z","nonce":"test"}'
```

### High Memory Usage

```bash
# Check blob counts
curl -sk https://localhost:8100/whisper/peer-data/stats | jq '.total_blobs'

# Clear old data (if needed)
sudo systemctl stop whisper-node
rm /home/ubuntu/wg-manager/whisper_data/peer_store.json
sudo systemctl start whisper-node
```

---

## Logging

### Log Locations

```bash
# Systemd logs
sudo journalctl -u whisper-node -f

# Filter by level
sudo journalctl -u whisper-node | grep -i error
sudo journalctl -u whisper-node | grep -i warning
```

### Log Format

```
2026-01-14 10:30:00 INFO whisper_node - Heartbeat sent to node15 (10.100.0.100)
2026-01-14 10:30:05 INFO whisper_node - Periodic mesh sync complete: 12 blobs synced
2026-01-14 10:30:10 WARNING whisper_node - Broadcast to 10.100.0.101 failed (attempt 1)
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.3.0 | 2026-01-14 | Added `own_identity_hash` to stats response |
| 1.2.0 | 2026-01-13 | Added periodic sync worker, broadcast retry |
| 1.1.0 | 2026-01-11 | Added CRL enforcement |
| 1.0.0 | 2026-01-10 | Initial release |
