# VPN Gateway API - WireGuard/AmneziaVPN Management

**Secure, high-performance VPN gateway API with HMAC authentication and optional payload encryption.**

---

## 🎯 Features

- ✅ WireGuard peer management via REST API
- ✅ HMAC-SHA256 authentication
- ✅ AES-256-GCM payload encryption (optional)
- ✅ Dual-stack IPv4/IPv6 support
- ✅ Thread-safe IP allocation
- ✅ Automatic peer reconstruction on startup
- ✅ Health monitoring endpoints
- ✅ SQLite database with automatic schema management
- 🔄 AmneziaVPN obfuscation support (planned)

---

## 📋 Prerequisites

- Ubuntu 24.04 LTS (or Debian 12)
- Python 3.12+
- WireGuard tools
- 4-8GB RAM (recommended for RAM-based operations)
- KVM-based VPS (for kernel module support)

---

## 🚀 Quick Start

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
git clone <YOUR_REPO_URL> wg-manager
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
cd gateway_api

# Create .env file (NEVER commit this!)
cat > .env <<EOF
GATEWAY_API_KEY=<generate with: openssl rand -hex 32>
GATEWAY_PUBLIC_KEY=<optional for encryption>
MAX_TIMESTAMP_DIFF=300
WG_IPV4_SUBNET=10.0.1.0/24
WG_IPV6_SUBNET=fd42:4242:1::/64
WG_DEFAULT_PORT=51820
DNS_SERVERS={"d1":"1.1.1.1","d2":"8.8.8.8","d3":"9.9.9.9"}
DB_PATH=./wireguard.db
EOF

chmod 600 .env
```

### 5. Generate SSL Certificates

```bash
# Get server's public IP
SERVER_IP=$(curl -s ifconfig.me)

# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=${SERVER_IP}"

chmod 600 key.pem cert.pem
```

### 6. Configure WireGuard

```bash
# Generate WireGuard keys
wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey

# Create config
sudo tee /etc/wireguard/wg0.conf > /dev/null <<EOF
[Interface]
PrivateKey = $(sudo cat /etc/wireguard/privatekey)
Address = 10.0.1.1/24, fd42:4242:1::1/64
ListenPort = 51820
SaveConfig = false
EOF

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Start WireGuard
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
```

### 7. Configure Firewall

```bash
# Allow WireGuard
sudo ufw allow 51820/udp comment "WireGuard"

# Allow API from backend IPs only (replace with your backend IPs)
sudo ufw allow from <BACKEND_IP_1> to any port 8000 proto tcp
sudo ufw allow from <BACKEND_IP_2> to any port 8000 proto tcp
sudo ufw deny 8000/tcp

# SSH rate limiting
sudo ufw limit 22222 comment "SSH"

# Set defaults
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default allow routed

# Enable
sudo ufw --force enable
```

### 8. Configure NAT

```bash
# Get network interface name
INTERFACE=$(ip route | grep default | awk '{print $5}')

# Add NAT rule
sudo iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o $INTERFACE -j MASQUERADE

# Save
sudo netfilter-persistent save
```

### 9. Set Up Systemd Service

```bash
sudo cp systemd/wg-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable wg-manager
sudo systemctl start wg-manager
```

### 10. Configure Sudo Permissions

```bash
# Allow ubuntu user to run wg command without password
echo "ubuntu ALL=(ALL) NOPASSWD: /usr/bin/wg" | sudo tee /etc/sudoers.d/wireguard-manager
sudo chmod 440 /etc/sudoers.d/wireguard-manager
```

### 11. Initialize Database

```bash
cd gateway_api
source ../venv/bin/activate
python3 -c "from database import init_db; init_db()"
```

### 12. Verify Installation

```bash
# Check services
sudo systemctl status wg-manager
sudo systemctl status wg-quick@wg0

# Check WireGuard
sudo wg show

# Test API (replace with actual HMAC signature)
curl -k https://localhost:8000/api/v1/server/status \
  -H "signature: <HMAC_SIGNATURE>" \
  -H "timestamp: $(date +%s)"
```

---

## 📖 API Endpoints

### Base URL
```
https://<gateway-ip>:8000
```

### Authentication
All endpoints require HMAC-SHA256 authentication:
- Header: `signature: <hmac_hex>`
- Header: `timestamp: <unix_timestamp>`

### Available Endpoints

#### Create Peer Configuration
```http
POST /api/v1/configurations/
```

#### Update Peer Status
```http
PUT /api/v1/configurations/{public_key}/status
```

#### Delete Peer
```http
DELETE /api/v1/configurations/{public_key}
```

#### Get IP Usage Statistics
```http
GET /api/v1/ip-usage
```

#### Get Server Status
```http
GET /api/v1/server/status
```

#### Get Detailed Metrics
```http
GET /api/v1/server/metrics
```

**Full API documentation:** See [docs/API.md](docs/API.md)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│         Backend Server                   │
│  - Account management                    │
│  - Subscription control                  │
│  - Source of truth                       │
└──────────────┬──────────────────────────┘
               │
               │ HTTPS + HMAC
               │ (Backend → Gateway only)
               ▼
┌─────────────────────────────────────────┐
│         Gateway Server                   │
│  ┌─────────────────────────────────┐   │
│  │   FastAPI Application            │   │
│  │   - Peer management              │   │
│  │   - HMAC auth                    │   │
│  │   - AES-GCM encryption           │   │
│  └──────────┬──────────────────────┘   │
│             ▼                            │
│  ┌─────────────────────────────────┐   │
│  │   WireGuard Manager              │   │
│  │   - IP allocation                │   │
│  │   - Peer creation/deletion       │   │
│  │   - Thread-safe operations       │   │
│  └──────────┬──────────────────────┘   │
│             ▼                            │
│  ┌─────────────────────────────────┐   │
│  │   WireGuard Kernel               │   │
│  │   - wg0 interface                │   │
│  │   - Peer tunnels                 │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

---

## 🔐 Security

### HMAC Authentication
- Algorithm: HMAC-SHA256
- Message format: `timestamp={unix_time}, body_length={length}`
- Time window: 60 seconds
- Constant-time comparison

### Payload Encryption (Optional)
- Algorithm: AES-256-GCM
- Key derivation: HKDF-SHA256
- IV: 12 bytes (random)
- Authenticated encryption

### Network Security
- API accessible only from whitelisted backend IPs
- HTTPS/TLS encryption
- UFW firewall
- Rate-limited SSH

---

## 📊 Monitoring

### Service Health
```bash
# Service status
sudo systemctl status wg-manager wg-quick@wg0

# Live logs
sudo journalctl -u wg-manager -f

# Recent logs
sudo journalctl -u wg-manager -n 100 --no-pager
```

### WireGuard Status
```bash
# All peers
sudo wg show

# Peer count
sudo wg show wg0 peers | wc -l

# Specific peer
sudo wg show wg0 peer <PUBLIC_KEY>
```

### Performance Metrics
```bash
# Via API
curl -k https://localhost:8000/api/v1/server/metrics \
  -H "signature: <HMAC>" \
  -H "timestamp: $(date +%s)"

# System resources
htop
free -h
df -h
```

---

## 🔧 Configuration

### Environment Variables (.env)

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `GATEWAY_API_KEY` | HMAC authentication key | Yes | `8f29c82c...` |
| `GATEWAY_PUBLIC_KEY` | Payload encryption key | No | `tqgwn3SO...` |
| `WG_IPV4_SUBNET` | IPv4 subnet for peers | Yes | `10.0.1.0/24` |
| `WG_IPV6_SUBNET` | IPv6 subnet for peers | Yes | `fd42:4242:1::/64` |
| `WG_DEFAULT_PORT` | WireGuard listen port | Yes | `51820` |
| `DNS_SERVERS` | DNS server options | Yes | `{"d1":"1.1.1.1",...}` |
| `DB_PATH` | SQLite database path | Yes | `./wireguard.db` |
| `MAX_TIMESTAMP_DIFF` | HMAC time window (sec) | No | `300` |

---

## 🐛 Troubleshooting

### API Won't Start
```bash
# Check port
sudo netstat -tlnp | grep 8000

# Check certificates
ls -lh gateway_api/key.pem gateway_api/cert.pem

# Check logs
sudo journalctl -u wg-manager -n 100
```

### Peers Can't Connect
```bash
# Check WireGuard
sudo wg show

# Check firewall
sudo ufw status verbose

# Check IP forwarding
sysctl net.ipv4.ip_forward

# Check NAT
sudo iptables -t nat -L -n -v
```

### HMAC Authentication Fails
```bash
# Check API key matches backend
grep GATEWAY_API_KEY .env

# Check time sync
date
# Should match backend server time within 60 seconds

# Check signature generation
# See docs/HMAC_AUTHENTICATION.md
```

---

## 📚 Documentation

- **[docs/API.md](docs/API.md)** - Complete API reference
- **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Deployment guide
- **[docs/SECURITY.md](docs/SECURITY.md)** - Security documentation
- **[docs/RAM_BASED.md](docs/RAM_BASED.md)** - RAM-based gateway setup
- **[docs/AMNEZIAVPN.md](docs/AMNEZIAVPN.md)** - AmneziaVPN integration

---

## 🔄 Development

### Running Locally

```bash
source venv/bin/activate
cd gateway_api
uvicorn main:app --reload --port 8000
```

### Testing

```bash
# Test peer creation
python3 tests/test_peer_creation.py

# Test authentication
python3 tests/test_hmac_auth.py
```

---

## 📞 Support

For issues or questions:
- Check logs: `sudo journalctl -u wg-manager`
- Review API docs: `docs/API.md`
- Security guide: `docs/SECURITY.md`

---

**Version:** 2.0  
**Status:** Production Ready  
**License:** Private/Proprietary  
**Last Updated:** December 8, 2025

