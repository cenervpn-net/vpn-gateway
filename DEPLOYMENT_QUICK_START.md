# VPN Gateway - Quick Deployment Guide

**For fresh Ubuntu 24.04 LTS server with 8GB RAM**

---

## 📋 Prerequisites

- Ubuntu 24.04 LTS server
- 8GB RAM, 2+ CPU cores
- Root/sudo access
- Git repository URL

---

## 🚀 10-Minute Deployment

### 1. System Setup (2 min)

```bash
# Update system
sudo apt update

# Install requirements
sudo apt install -y \
  wireguard wireguard-tools \
  python3 python3-venv python3-pip \
  ufw iptables-persistent git curl

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 2. Clone Repository (1 min)

```bash
cd /home/ubuntu
git clone <YOUR_REPO_URL> wg-manager
cd wg-manager
```

### 3. Python Environment (2 min)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure Environment (2 min)

```bash
cd gateway_api

# Copy template
cp ../.env.example .env

# Generate API key
API_KEY=$(openssl rand -hex 32)

# Edit .env (replace X with gateway number: 1, 2, 3...)
sed -i "s/openssl rand -hex 32/$API_KEY/" .env
sed -i "s/10.0.X.0/10.0.3.0/" .env        # Gateway 3 example
sed -i "s/fd42:4242:X::/fd42:4242:3::/" .env

# Or edit manually
vi .env
```

### 5. SSL Certificates (1 min)

```bash
# Still in gateway_api/
SERVER_IP=$(curl -s ifconfig.me)

openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/C=US/O=VPNGateway/CN=${SERVER_IP}"

chmod 600 key.pem cert.pem
```

### 6. WireGuard Setup (2 min)

```bash
# Generate keys
wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey

# Get gateway number from .env
GATEWAY_NUM=$(grep WG_IPV4_SUBNET .env | cut -d. -f3)
IPV4_GW="10.0.${GATEWAY_NUM}.1"
IPV6_GW="fd42:4242:${GATEWAY_NUM}::1"

# Create config
sudo tee /etc/wireguard/wg0.conf > /dev/null <<EOF
[Interface]
PrivateKey = $(sudo cat /etc/wireguard/privatekey)
Address = ${IPV4_GW}/24, ${IPV6_GW}/64
ListenPort = 51820
SaveConfig = false
EOF

# Start
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
```

### 7. Firewall (1 min)

```bash
# Allow WireGuard
sudo ufw allow 51820/udp

# Allow API from backend IPs (REPLACE WITH YOUR BACKEND IPS!)
sudo ufw allow from 135.148.39.216 to any port 8000 proto tcp
sudo ufw allow from 46.109.51.133 to any port 8000 proto tcp
sudo ufw deny 8000/tcp

# SSH
sudo ufw limit 22222

# Enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default allow routed
sudo ufw --force enable
```

### 8. NAT Configuration (1 min)

```bash
INTERFACE=$(ip route | grep default | awk '{print $5}')
GATEWAY_NUM=$(grep WG_IPV4_SUBNET /home/ubuntu/wg-manager/gateway_api/.env | cut -d. -f3)
SUBNET="10.0.${GATEWAY_NUM}.0/24"

sudo iptables -t nat -A POSTROUTING -s $SUBNET -o $INTERFACE -j MASQUERADE
sudo netfilter-persistent save
```

### 9. Systemd Service (1 min)

```bash
cd /home/ubuntu/wg-manager

sudo cp systemd/wg-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable wg-manager
sudo systemctl start wg-manager
```

### 10. Sudo Permissions (<1 min)

```bash
echo "ubuntu ALL=(ALL) NOPASSWD: /usr/bin/wg" | sudo tee /etc/sudoers.d/wireguard-manager
sudo chmod 440 /etc/sudoers.d/wireguard-manager
```

### 11. Initialize Database (<1 min)

```bash
cd /home/ubuntu/wg-manager/gateway_api
source ../venv/bin/activate
python3 -c "from database import init_db; init_db()"
```

### 12. Verify (1 min)

```bash
# Check services
sudo systemctl status wg-manager wg-quick@wg0

# Check WireGuard
sudo wg show

# Check API
curl -k https://localhost:8000/api/v1/server/status \
  -H "signature: test" \
  -H "timestamp: $(date +%s)"
# Will return 401 (expected without valid HMAC), but confirms API is running
```

---

## 📊 Deployment Checklist

- [ ] System packages installed
- [ ] Repository cloned
- [ ] Python environment created
- [ ] Dependencies installed
- [ ] .env configured (API key, subnets)
- [ ] SSL certificates generated
- [ ] WireGuard interface configured and running
- [ ] Firewall rules applied
- [ ] NAT configured
- [ ] Systemd service installed and running
- [ ] Sudo permissions granted
- [ ] Database initialized
- [ ] API responding to requests
- [ ] Backend database entry created

---

## 🔧 Backend Integration

### After Gateway Deployment:

```sql
-- Add to backend vpn_gateways table
INSERT INTO vpn_gateways (
    id, name, location, hostname,
    ipv4_address, ipv6_address,
    ports, port,
    api_address, api_port,
    api_key, public_key,
    is_active
) VALUES (
    3,                                    -- Gateway number
    'Gateway3',
    'US',
    '<hostname>',
    '<ipv4>',
    '<ipv6>',
    ARRAY[51820,53,443,8099],
    51820,
    'https://<hostname_or_ip>',
    8000,
    '<api_key_from_env>',
    '<wireguard_public_key>',
    false                                 -- Start inactive for testing
);
```

### Test from Backend:

```bash
# Generate HMAC signature and test
cd /home/ubuntu/vpn_service/backend_v2
# Test gateway API connection
```

---

## ⚡ 8GB RAM Benefits

With 8GB RAM, you can:
- ✅ Run completely in RAM (tmpfs)
- ✅ In-memory database (blazing fast)
- ✅ Handle 1000+ concurrent peers
- ✅ Compile kernel modules in 2-3 minutes (6 cores!)
- ✅ Plenty of headroom for AmneziaVPN

---

## 🎯 Next Steps After Basic Deployment

1. **Test peer creation from backend**
2. **Implement RAM-based architecture** (optional)
3. **Install AmneziaVPN** (Phase A-D)
4. **Activate gateway** (set is_active=true)
5. **Production testing**

---

**Total deployment time: 15-20 minutes** ⚡

**Documentation:** See [README.md](README.md) for detailed information.

