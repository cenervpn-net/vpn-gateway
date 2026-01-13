# VPN Gateway API - WireGuard/AmneziaWG Management

**Secure, high-performance VPN gateway with distributed mesh peer recovery, HMAC authentication, and AmneziaWG obfuscation support.**

---

## Overview

This gateway API provides enterprise-grade WireGuard peer management with a unique **zero-knowledge mesh recovery system**. Peer configurations are encrypted and distributed across the mesh network, enabling automatic recovery after gateway reprovisioning without the backend ever seeing plaintext peer data.

---

## Key Features

### Core VPN Management
- WireGuard & AmneziaWG peer management via REST API
- HMAC-SHA256 request authentication
- AES-256-GCM payload encryption (optional)
- Dual-stack IPv4/IPv6 support
- Thread-safe IP allocation
- Automatic peer reconstruction on startup

### Mesh Peer Recovery System
- **Zero-knowledge architecture**: Backend stores only encrypted blobs
- **Distributed storage**: Peer configs replicated across mesh nodes
- **Automatic recovery**: Peers restored on gateway reboot/reprovision
- **Periodic sync**: Gateways sync mesh state every 10 minutes
- **Orphan detection**: Automatic cleanup of stale peer data

### Whisper Node (Gateway-to-Gateway)
- mTLS-secured inter-gateway communication
- Heartbeat-based health monitoring
- Mesh-wide peer broadcast with retry logic
- CRL enforcement for certificate revocation

### AmneziaWG Obfuscation
- Multiple obfuscation levels (off, low, medium, high, extreme)
- Junk packet injection
- Custom magic headers
- Deep packet inspection resistance

---

## Architecture

```
                     ┌──────────────────────────────┐
                     │        Backend Server         │
                     │   - Account management        │
                     │   - Subscription control      │
                     │   - Stores ONLY encrypted     │
                     │     peer blobs (zero-knowledge)│
                     └──────────────┬───────────────┘
                                    │
                     ┌──────────────┴───────────────┐
                     │    Backend Mesh Nodes (2x)    │
                     │   - Persistent blob storage   │
                     │   - 2x replication            │
                     │   - Orphan auto-purge         │
                     └──────────────┬───────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼                         ▼                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Gateway 1      │◄───►│   Gateway 2      │◄───►│   Gateway N      │
│ ┌─────────────┐ │     │ ┌─────────────┐ │     │ ┌─────────────┐ │
│ │ Whisper Node│ │     │ │ Whisper Node│ │     │ │ Whisper Node│ │
│ │  - mTLS     │ │     │ │  - mTLS     │ │     │ │  - mTLS     │ │
│ │  - Mesh sync│ │     │ │  - Mesh sync│ │     │ │  - Mesh sync│ │
│ └─────────────┘ │     │ └─────────────┘ │     │ └─────────────┘ │
│ ┌─────────────┐ │     │ ┌─────────────┐ │     │ ┌─────────────┐ │
│ │ WG Manager  │ │     │ │ WG Manager  │ │     │ │ WG Manager  │ │
│ │  - REST API │ │     │ │  - REST API │ │     │ │  - REST API │ │
│ └─────────────┘ │     │ └─────────────┘ │     │ └─────────────┘ │
│ ┌─────────────┐ │     │ ┌─────────────┐ │     │ ┌─────────────┐ │
│ │  WireGuard  │ │     │ │  WireGuard  │ │     │ │  WireGuard  │ │
│ └─────────────┘ │     │ └─────────────┘ │     │ └─────────────┘ │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

---

## Prerequisites

- Ubuntu 24.04 LTS (or Debian 12)
- Python 3.12+
- WireGuard tools (+ AmneziaWG for obfuscation)
- 4-8GB RAM
- KVM-based VPS (for kernel module support)

---

## Quick Start

### 1. Install System Requirements

```bash
sudo apt update
sudo apt install -y \
  wireguard wireguard-tools \
  python3 python3-venv python3-pip \
  ufw iptables-persistent \
  git
```

### 2. Clone Repository

```bash
cd /home/ubuntu
git clone https://github.com/centervpn/vpn-gateway.git wg-manager
cd wg-manager
```

### 3. Install Python Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cat > .env <<EOF
# Gateway API Authentication
GATEWAY_API_KEY=<generate with: openssl rand -hex 32>
GATEWAY_PUBLIC_KEY=<optional for encryption>
MAX_TIMESTAMP_DIFF=300

# WireGuard Configuration
WG_IPV4_SUBNET=10.0.1.0/24
WG_IPV6_SUBNET=fd42:4242:1::/64
WG_DEFAULT_PORT=51820
DNS_SERVERS={"d1":"1.1.1.1","d2":"8.8.8.8","d3":"9.9.9.9"}

# Database
DB_PATH=./wireguard.db

# Whisper Node (Mesh)
WHISPER_VERSION=1.3.0
MESH_PEER_ADDRESSES=10.100.0.100:8100,10.100.0.101:8100
BACKEND_MESH_ADDRESSES=127.0.0.1:8101,127.0.0.1:8102
EOF

chmod 600 .env
```

### 5. Set Up Systemd Services

```bash
# Main WireGuard Manager API
sudo cp systemd/wg-manager.service /etc/systemd/system/

# Whisper Node (Mesh Communication)
sudo cp systemd/whisper-node.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable wg-manager whisper-node
sudo systemctl start wg-manager whisper-node
```

### 6. Verify Installation

```bash
# Check services
sudo systemctl status wg-manager whisper-node

# Check WireGuard
sudo wg show

# Check Whisper Node
curl -sk https://localhost:8100/status
```

---

## API Endpoints

### WireGuard Manager (Port 8000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/configurations/` | Create peer configuration |
| PUT | `/api/v1/configurations/{pubkey}/status` | Update peer status |
| DELETE | `/api/v1/configurations/{pubkey}` | Delete peer |
| GET | `/api/v1/ip-usage` | Get IP allocation stats |
| GET | `/api/v1/server/status` | Get server status |
| GET | `/api/v1/server/metrics` | Get detailed metrics |

### Whisper Node (Port 8100)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status` | Node health status |
| GET | `/whisper/peer-data/stats` | Mesh storage statistics |
| POST | `/whisper/peer-data/store` | Store encrypted peer blob |
| POST | `/whisper/peer-data/retrieve` | Retrieve peer blobs |
| POST | `/whisper/mesh/sync` | Full mesh synchronization |
| POST | `/whisper/heartbeat` | Inter-gateway heartbeat |

---

## Mesh Peer Recovery

### How It Works

1. **Peer Creation**: When a peer is created, its configuration is:
   - Encrypted with gateway's derived key
   - Broadcast to all mesh nodes (gateways + backend)
   - Stored with identity hash for ownership

2. **Gateway Recovery**: On startup, the gateway:
   - Queries mesh for blobs matching its identity hash
   - Decrypts and restores peer configurations
   - Falls back to WireGuard interface scan if mesh is empty

3. **Periodic Sync**: Every 10 minutes:
   - Gateway syncs all blobs from mesh
   - Ensures consistency across nodes
   - Detects and reports orphaned blobs

### Identity Hash

Each gateway is identified by a SHA256 hash of its WireGuard public key:

```python
identity_hash = sha256(wg_public_key.encode()).hexdigest()[:16]
# Example: "d564e8b81e63d43d"
```

### Orphan Detection

Blobs are flagged as "orphaned" when:
- The owning gateway has been deleted
- The gateway's identity no longer matches any active gateway
- Auto-purged after 7 days of orphan status

---

## Security

### Authentication
- **HMAC-SHA256**: All API requests signed with shared secret
- **mTLS**: Inter-gateway communication uses mutual TLS
- **Certificate Revocation**: CRL enforcement for compromised certs

### Encryption
- **AES-256-GCM**: Optional payload encryption
- **Zero-knowledge mesh**: Backend never sees plaintext peer configs
- **HKDF key derivation**: Secure key generation from secrets

### Network
- **Firewall**: UFW with strict ingress rules
- **IP whitelist**: API accessible only from backend
- **Rate limiting**: SSH and API rate limits

---

## Monitoring

### Service Health

```bash
# All services
sudo systemctl status wg-manager whisper-node wg-quick@wg0

# Logs
sudo journalctl -u wg-manager -f
sudo journalctl -u whisper-node -f
```

### Mesh Status

```bash
# Local mesh stats
curl -sk https://localhost:8100/whisper/peer-data/stats | jq

# Response includes:
# - total_identities: Number of gateways with stored blobs
# - total_blobs: Total peer configurations stored
# - own_identity_hash: This gateway's identity
# - own_blobs: Blobs belonging to this gateway
```

### Dashboard

Access the admin dashboard at `https://call.centervpn.net/#/mesh-dashboard` for:
- Real-time mesh health
- Backend node status
- Gateway connectivity
- Orphaned blob detection

---

## Configuration Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GATEWAY_API_KEY` | HMAC authentication key | Required |
| `WHISPER_VERSION` | Software version string | `1.0.0` |
| `WG_IPV4_SUBNET` | IPv4 allocation pool | `10.0.1.0/24` |
| `WG_IPV6_SUBNET` | IPv6 allocation pool | `fd42:4242:1::/64` |
| `MESH_PEER_ADDRESSES` | Other gateway addresses | `` |
| `BACKEND_MESH_ADDRESSES` | Backend mesh node addresses | `` |
| `HEARTBEAT_INTERVAL` | Heartbeat frequency (sec) | `10` |
| `PERIODIC_MESH_SYNC_INTERVAL` | Full sync frequency (sec) | `600` |

---

## Troubleshooting

### Peers Not Recovering

```bash
# Check mesh connectivity
curl -sk https://localhost:8100/whisper/peer-data/stats | jq '.own_blobs'

# Check identity hash matches
curl -sk https://localhost:8100/whisper/peer-data/stats | jq '.own_identity_hash'

# Force mesh sync
curl -sk -X POST https://localhost:8100/whisper/mesh/sync
```

### Whisper Node Won't Start

```bash
# Check certificates
ls -la /home/ubuntu/wg-manager/gateway_api/cert.pem key.pem ca.crt

# Check port
sudo netstat -tlnp | grep 8100

# Check logs
sudo journalctl -u whisper-node -n 100
```

### All Blobs Showing as Orphaned

This typically indicates an identity hash mismatch. Verify:
```bash
# Gateway's own identity hash
curl -sk https://localhost:8100/whisper/peer-data/stats | jq '.own_identity_hash'

# Should match one of the identity_hash values in storage_summary
curl -sk https://localhost:8100/whisper/peer-data/stats | jq '.storage_summary[].identity_hash'
```

---

## Documentation

- **[docs/MESH_RECOVERY.md](docs/MESH_RECOVERY.md)** - Detailed mesh recovery documentation
- **[docs/WHISPER_NODE.md](docs/WHISPER_NODE.md)** - Whisper Node protocol
- **[docs/AMNEZIAWG.md](docs/AMNEZIAWG.md)** - AmneziaWG obfuscation setup
- **[DEPLOYMENT_QUICK_START.md](DEPLOYMENT_QUICK_START.md)** - Quick deployment guide

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.3.0 | 2026-01-14 | Fixed orphan detection identity hash matching |
| 1.2.0 | 2026-01-13 | Added periodic mesh sync, broadcast retry |
| 1.1.0 | 2026-01-11 | Added WireGuard fallback recovery |
| 1.0.0 | 2026-01-10 | Initial mesh peer recovery system |

---

**Version:** 1.3.0  
**Status:** Production  
**License:** Proprietary  
**Last Updated:** January 14, 2026
