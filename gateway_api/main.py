# gateway_api/main.py
# RAM-ONLY MODE - No SQLite dependency
import os
import asyncio
import subprocess
import hmac
import hashlib
import time
from fastapi import FastAPI, Depends, HTTPException, Header, BackgroundTasks, Request
from typing import Optional, List
from pydantic import BaseModel
import json
import logging
import psutil
from security import verify_admin_request
from wg_manager import WireGuardManager
from datetime import datetime
from e2e_crypto import (
    init_e2e_crypto, 
    is_e2e_request, 
    decrypt_e2e_request, 
    encrypt_e2e_response,
    E2EContext
)

# RAM-only peer storage (replaces SQLite)
from peer_store import get_peer_store, PeerConfig, PeerStore

# CRL Enforcement for mesh security
from crl_enforcement import (
    load_crl_from_disk, 
    is_certificate_revoked, 
    get_crl_status,
    refresh_crl_cache
)

# Mesh Peer Sync for RAM-only recovery
try:
    from mesh_peer_sync import (
        on_peer_created, 
        on_peer_updated, 
        on_peer_deleted, 
        on_peer_suspended,
        on_peer_resumed,
        recover_peers,
        query_suspended_peer
    )
    MESH_SYNC_AVAILABLE = True
except ImportError:
    MESH_SYNC_AVAILABLE = False
    logging.warning("Mesh peer sync not available - peer recovery disabled")


def _parse_bool_env(value: str, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in ("0", "false", "no", "off")


# Mesh reconciliation settings (apply mesh state to WG when gateway is online)
MESH_RECONCILE_INTERVAL = int(os.environ.get("MESH_RECONCILE_INTERVAL", "60"))
MESH_RECONCILE_REQUIRE_QUORUM = _parse_bool_env(
    os.environ.get("MESH_RECONCILE_REQUIRE_QUORUM", "true"), default=True
)
MESH_RECONCILE_PRUNE_MISSING = _parse_bool_env(
    os.environ.get("MESH_RECONCILE_PRUNE_MISSING", "true"), default=True
)


# Set up logging
logging.basicConfig(level=logging.INFO)  # INFO in production, DEBUG only for troubleshooting
logger = logging.getLogger(__name__)

app = FastAPI()
wg = WireGuardManager()

# Global peer store instance
peer_store: PeerStore = get_peer_store()

@app.on_event("startup")
async def startup_event():
    """
    RAM-only startup: Recover peers from mesh into memory.
    No SQLite database is used.
    """
    logger.info("Gateway starting up in RAM-ONLY mode")
    
    # Recover peers from mesh network
    if MESH_SYNC_AVAILABLE:
        try:
            logger.info("Recovering peers from mesh network...")
            result = await recover_peers()
            
            if result.success:
                # Populate in-memory store with recovered peers
                active_count = 0
                suspended_count = 0
                
                for peer_config in result.recovered_configs:
                    if peer_config.get("_deleted"):
                        continue
                    
                    public_key = peer_config.get("public_key")
                    if not public_key:
                        continue
                    
                    # Create PeerConfig from mesh data
                    config = PeerConfig(
                        public_key=public_key,
                        status=peer_config.get("status", "active"),
                        assigned_ip=peer_config.get("assigned_ip", ""),
                        assigned_ipv6=peer_config.get("assigned_ipv6", ""),
                        assigned_port=peer_config.get("assigned_port", 0),
                        tunnel_traffic=peer_config.get("tunnel_traffic", "all"),
                        dns_choice=peer_config.get("dns_choice", ""),
                        allowed_ips=peer_config.get("allowed_ips", ""),
                        obfuscation_level=peer_config.get("obfuscation_level", "off"),
                        obfuscation_enabled=peer_config.get("obfuscation_enabled", False),
                        junk_packet_count=peer_config.get("junk_packet_count", 0),
                        junk_packet_min_size=peer_config.get("junk_packet_min_size", 0),
                        junk_packet_max_size=peer_config.get("junk_packet_max_size", 0),
                        init_packet_junk_size=peer_config.get("init_packet_junk_size", 0),
                        response_packet_junk_size=peer_config.get("response_packet_junk_size", 0),
                        underload_packet_junk_size=peer_config.get("underload_packet_junk_size", 0),
                        transport_packet_junk_size=peer_config.get("transport_packet_junk_size", 0),
                        init_packet_magic_header=peer_config.get("init_packet_magic_header", 0),
                        response_packet_magic_header=peer_config.get("response_packet_magic_header", 0),
                        underload_packet_magic_header=peer_config.get("underload_packet_magic_header", 0),
                        transport_packet_magic_header=peer_config.get("transport_packet_magic_header", 0)
                    )
                    
                    # Add to memory store
                    peer_store.add(config)
                    
                    # Add active peers to WireGuard
                    if config.status == "active":
                        obf_level = config.obfuscation_level or 'off'
                        success, _, _ = wg.add_peer(
                            public_key,
                            protocol='dual' if config.assigned_ipv6 else None,
                            tunnel_traffic=config.tunnel_traffic,
                            port=config.assigned_port,
                            assigned_ipv4=config.assigned_ip,
                            assigned_ipv6=config.assigned_ipv6,
                            obfuscation_level=obf_level
                        )
                        if success:
                            active_count += 1
                    else:
                        suspended_count += 1
                
                peer_store.initialize()
                logger.info(f"Mesh recovery complete: {active_count} active, {suspended_count} suspended peers")
            else:
                logger.warning(f"Mesh recovery failed: {result.message}")
                peer_store.initialize()  # Initialize empty store
                
        except Exception as e:
            logger.error(f"Mesh recovery error: {e}")
            peer_store.initialize()  # Initialize empty store
    else:
        logger.warning("Mesh sync not available - starting with empty peer store")
        peer_store.initialize()
    
    # FALLBACK: If peer_store is empty but WireGuard has peers, scan and rebuild
    if len(peer_store.get_all()) == 0:
        logger.info("Peer store is empty - scanning WireGuard for existing peers...")
        try:
            from mesh_peer_sync import on_peer_created
            import asyncio
            
            interface_obf_map = {'wg0': 'off', 'wg1': 'basic', 'wg2': 'high', 'wg3': 'stealth'}
            recovered_from_wg = 0
            seen_pubkeys = set()  # Deduplicate peers across interfaces
            
            for interface in ['wg0', 'wg1', 'wg2', 'wg3']:
                try:
                    result = wg.run_wg_command(['show', interface, 'peers'])
                    if result.returncode != 0 or not result.stdout.strip():
                        continue
                    
                    for public_key in result.stdout.strip().split('\n'):
                        if not public_key:
                            continue
                        
                        # Skip if we already processed this peer on another interface
                        if public_key in seen_pubkeys:
                            logger.debug(f"Skipping duplicate peer {public_key[:20]}... on {interface}")
                            continue
                        seen_pubkeys.add(public_key)
                        
                        # Get allowed IPs for this peer
                        allowed_result = wg.run_wg_command(['show', interface, 'allowed-ips'])
                        assigned_ip = ""
                        if allowed_result.returncode == 0:
                            for line in allowed_result.stdout.strip().split('\n'):
                                if public_key in line:
                                    parts = line.split('\t')
                                    if len(parts) >= 2:
                                        ip_part = parts[1].strip().split('/')[0]
                                        if ip_part and ip_part != '(none)':
                                            assigned_ip = ip_part
                                    break
                        
                        obf_level = interface_obf_map.get(interface, 'off')
                        
                        # Create minimal peer config
                        config = PeerConfig(
                            public_key=public_key,
                            status="active",
                            assigned_ip=assigned_ip,
                            assigned_ipv6="",
                            assigned_port=0,
                            tunnel_traffic="all",
                            dns_choice="",
                            allowed_ips=f"{assigned_ip}/32" if assigned_ip else "",
                            obfuscation_level=obf_level,
                            obfuscation_enabled=(obf_level != 'off'),
                        )
                        
                        peer_store.add(config)
                        recovered_from_wg += 1
                        logger.info(f"Recovered peer from WireGuard: {public_key[:20]}... on {interface}")
                        
                        # Broadcast to mesh
                        if MESH_SYNC_AVAILABLE:
                            peer_config_for_mesh = {
                                "public_key": public_key,
                                "assigned_ip": assigned_ip,
                                "assigned_ipv6": "",
                                "assigned_port": 0,
                                "tunnel_traffic": "all",
                                "dns_choice": "",
                                "allowed_ips": f"{assigned_ip}/32" if assigned_ip else "",
                                "obfuscation_level": obf_level,
                                "status": "active",
                            }
                            try:
                                await on_peer_created(peer_config_for_mesh)
                                logger.debug(f"Broadcast recovered peer to mesh: {public_key[:20]}...")
                            except Exception as e:
                                logger.warning(f"Failed to broadcast recovered peer: {e}")
                
                except Exception as e:
                    logger.warning(f"Error scanning {interface}: {e}")
            
            if recovered_from_wg > 0:
                logger.info(f"Recovered {recovered_from_wg} unique peers from WireGuard and broadcast to mesh")
        except Exception as e:
            logger.error(f"WireGuard fallback recovery error: {e}")
    
    # NOTE: In RAM-only mode, we skip sync_and_reconstruct_peers() because:
    # 1. We already added recovered peers to WireGuard above
    # 2. sync_and_reconstruct_peers() would remove them and try to read from SQLite (which doesn't exist)
    # Instead, just sync the IP tracking from current WireGuard state
    logger.info("Syncing IP tracking from WireGuard state...")
    try:
        wg.sync_assigned_ips_from_wireguard()
        logger.info("IP tracking sync completed")
    except Exception as e:
        logger.warning(f"IP tracking sync failed (non-fatal): {e}")

    # Start mesh reconciliation loop (apply mesh state to WG when online)
    if MESH_SYNC_AVAILABLE and MESH_RECONCILE_INTERVAL > 0:
        asyncio.create_task(mesh_reconcile_loop())
        logger.info(f"Mesh reconcile loop started (interval={MESH_RECONCILE_INTERVAL}s)")
    
    # Load CRL for mesh security enforcement
    if load_crl_from_disk():
        crl_status = get_crl_status()
        logger.info(f"CRL enforcement active: v{crl_status['version']} with {crl_status['entries_count']} revoked certs")
    else:
        logger.info("CRL enforcement: No CRL loaded (will be synced from mesh)")
    
    # Initialize E2E encryption if configured
    e2e = init_e2e_crypto()
    if e2e:
        logger.info(f"E2E encryption enabled. ECDH public key: {e2e.public_key_b64[:20]}...")
    else:
        logger.warning("E2E encryption disabled (ECDH_PRIVATE_KEY not set)")

class ObfuscationConfig(BaseModel):
    """AmneziaWG obfuscation parameters"""
    enabled: bool = True
    jc: Optional[int] = 3      # Junk packet count (0-128)
    jmin: Optional[int] = 50   # Min junk size (0-1280)
    jmax: Optional[int] = 1000 # Max junk size (0-1280)
    s1: Optional[int] = 0      # Init packet junk size
    s2: Optional[int] = 0      # Response packet junk size
    s3: Optional[int] = 0      # Under load packet junk size
    s4: Optional[int] = 0      # Transport packet junk size
    h1: Optional[int] = 1      # Init packet magic header
    h2: Optional[int] = 2      # Response packet magic header
    h3: Optional[int] = 3      # Under load packet magic header
    h4: Optional[int] = 4      # Transport packet magic header
    
    class Config:
        extra = "allow"

class ConfigCreate(BaseModel):
    # Legacy required fields
    public_key: str
    request_id: Optional[str] = None  # Optional for E2E (inside encrypted blob)
    
    # New optional fields with legacy defaults
    protocol: Optional[str] = None  # None = IPv4 (legacy)
    tunnel_traffic: Optional[List[str]] = ['ipv4']  # Legacy default
    port: Optional[int] = 51820  # Legacy default
    dns: Optional[str] = 'd1'  # Legacy default
    
    # AmneziaWG obfuscation parameters
    obfuscation: Optional[ObfuscationConfig] = None
    
    # E2E encryption fields (backend cannot decrypt - Zero-Knowledge mode)
    eph_pub: Optional[str] = None        # Client's ephemeral X25519 public key
    encrypted_blob: Optional[str] = None  # E2E encrypted config
    
    # Obfuscation level for interface selection
    obfuscation_level: Optional[str] = None  # off, basic, high, stealth
    
    class Config:
        extra = "allow"  # Allow extra fields

class ConfigStatus(BaseModel):
    status: str  # active/suspended

async def mesh_suspend_task(public_key: str):
    """Background task to update mesh status to suspended"""
    try:
        await on_peer_suspended(public_key)
        logger.info(f"Mesh status updated to suspended for peer: {public_key[:20]}...")
    except Exception as e:
        logger.warning(f"Failed to update mesh status for suspend: {e}")


async def mesh_resume_task(public_key: str):
    """Background task to update mesh status to active"""
    try:
        await on_peer_resumed(public_key)
        logger.info(f"Mesh status updated to active for peer: {public_key[:20]}...")
    except Exception as e:
        logger.warning(f"Failed to update mesh status for resume: {e}")


def _normalize_tunnel_traffic(value):
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        if value == "all":
            return ["ipv4", "ipv6"]
        if value:
            return [value]
    return ["ipv4"]


def _normalize_allowed_ips(value):
    if isinstance(value, list):
        return ",".join(value)
    return value or ""


def _peer_config_from_mesh(mesh_config: dict, status_override: Optional[str] = None) -> PeerConfig:
    status = status_override or mesh_config.get("status", "active")
    return PeerConfig(
        public_key=mesh_config.get("public_key", ""),
        status=status,
        assigned_ip=mesh_config.get("assigned_ip", ""),
        assigned_ipv6=mesh_config.get("assigned_ipv6", ""),
        assigned_port=int(mesh_config.get("assigned_port") or 0),
        tunnel_traffic=_normalize_tunnel_traffic(mesh_config.get("tunnel_traffic", "all")),
        dns_choice=mesh_config.get("dns_choice", ""),
        allowed_ips=_normalize_allowed_ips(mesh_config.get("allowed_ips", "")),
        obfuscation_level=mesh_config.get("obfuscation_level", "off"),
        obfuscation_enabled=mesh_config.get("obfuscation_enabled", False),
        junk_packet_count=mesh_config.get("junk_packet_count", 0),
        junk_packet_min_size=mesh_config.get("junk_packet_min_size", 0),
        junk_packet_max_size=mesh_config.get("junk_packet_max_size", 0),
        init_packet_junk_size=mesh_config.get("init_packet_junk_size", 0),
        response_packet_junk_size=mesh_config.get("response_packet_junk_size", 0),
        underload_packet_junk_size=mesh_config.get("underload_packet_junk_size", 0),
        transport_packet_junk_size=mesh_config.get("transport_packet_junk_size", 0),
        init_packet_magic_header=mesh_config.get("init_packet_magic_header", 0),
        response_packet_magic_header=mesh_config.get("response_packet_magic_header", 0),
        underload_packet_magic_header=mesh_config.get("underload_packet_magic_header", 0),
        transport_packet_magic_header=mesh_config.get("transport_packet_magic_header", 0)
    )


async def reconcile_peers_from_mesh():
    """
    Reconcile local peers with mesh state.
    Mesh is authoritative; stale peers are removed when enabled.
    """
    if not MESH_SYNC_AVAILABLE or not peer_store.is_initialized:
        return {
            "status": "unavailable",
            "message": "Mesh sync not available or peer store not initialized"
        }

    result = await recover_peers(require_quorum=MESH_RECONCILE_REQUIRE_QUORUM)
    if not result.success:
        logger.warning(f"Mesh reconcile skipped: {result.message}")
        return {
            "status": "skipped",
            "message": result.message
        }

    mesh_configs = [c for c in result.recovered_configs if c.get("public_key")]
    mesh_by_key = {c["public_key"]: c for c in mesh_configs}
    mesh_keys = set(mesh_by_key.keys())

    applied_active = 0
    applied_suspended = 0
    applied_deleted = 0

    for public_key, cfg in mesh_by_key.items():
        status = cfg.get("status", "active")

        if status == "deleted":
            if wg.verify_peer_exists(public_key):
                wg.remove_peer(public_key)
            if peer_store.exists(public_key):
                peer_store.delete(public_key)
            applied_deleted += 1
            continue

        if status == "suspended":
            if wg.verify_peer_exists(public_key):
                wg.remove_peer(public_key)
            if peer_store.exists(public_key):
                peer_store.update(public_key, status="suspended")
            else:
                peer_store.add(_peer_config_from_mesh(cfg, status_override="suspended"))
            applied_suspended += 1
            continue

        # Active peers
        if peer_store.exists(public_key):
            peer_store.update(public_key, status="active")
        else:
            peer_store.add(_peer_config_from_mesh(cfg, status_override="active"))

        if not wg.verify_peer_exists(public_key):
            assigned_ip = cfg.get("assigned_ip") or None
            assigned_ipv6 = cfg.get("assigned_ipv6") or None
            if not assigned_ip and not assigned_ipv6:
                logger.warning(f"Mesh peer missing IPs: {public_key[:20]}... (skip add)")
            else:
                obf_level = cfg.get("obfuscation_level", "off") or "off"
                success, _, _ = wg.add_peer(
                    public_key,
                    protocol='dual' if assigned_ipv6 else None,
                    tunnel_traffic=_normalize_tunnel_traffic(cfg.get("tunnel_traffic", "all")),
                    port=int(cfg.get("assigned_port") or 0),
                    assigned_ipv4=assigned_ip,
                    assigned_ipv6=assigned_ipv6,
                    obfuscation_level=obf_level
                )
                if not success:
                    logger.warning(f"Failed to activate mesh peer: {public_key[:20]}...")
        applied_active += 1

    if MESH_RECONCILE_PRUNE_MISSING:
        for peer in peer_store.get_all():
            if peer.public_key not in mesh_keys:
                if wg.verify_peer_exists(peer.public_key):
                    wg.remove_peer(peer.public_key)
                peer_store.delete(peer.public_key)
                applied_deleted += 1

    logger.info(
        "Mesh reconcile complete: active=%d suspended=%d deleted=%d",
        applied_active, applied_suspended, applied_deleted
    )

    return {
        "status": "ok",
        "mesh_total": len(mesh_configs),
        "applied_active": applied_active,
        "applied_suspended": applied_suspended,
        "applied_deleted": applied_deleted
    }


async def mesh_reconcile_loop():
    if MESH_RECONCILE_INTERVAL <= 0:
        return
    # Small delay to allow startup recovery to finish
    await asyncio.sleep(10)
    while True:
        try:
            await reconcile_peers_from_mesh()
        except Exception as e:
            logger.warning(f"Mesh reconcile error: {e}")
        await asyncio.sleep(MESH_RECONCILE_INTERVAL)

@app.post("/api/v1/configurations/")
async def create_configuration(
    request: Request,
    background_tasks: BackgroundTasks,
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    # Get raw body for signature verification
    raw_body = await request.body()
    body_str = raw_body.decode('utf-8')
    verify_admin_request(signature, timestamp, body_str)
    
    # Parse config from raw body
    config_data = json.loads(body_str)
    config = ConfigCreate(**config_data)
    
    # E2E context for response encryption (None if plaintext mode)
    e2e_ctx: Optional[E2EContext] = None
    
    # E2E encryption for Zero-Knowledge mode
    if config.eph_pub and config.encrypted_blob:
        logger.info("E2E encrypted request received")
        try:
            decrypted_config, e2e_ctx = decrypt_e2e_request(config_data)
            
            # Update config with decrypted values
            if 'protocol' in decrypted_config:
                config.protocol = decrypted_config['protocol']
            if 'tunnel_traffic' in decrypted_config:
                config.tunnel_traffic = decrypted_config['tunnel_traffic']
            if 'dns' in decrypted_config:
                config.dns = decrypted_config['dns']
            if 'port' in decrypted_config:
                config.port = decrypted_config['port']
            if 'request_id' in decrypted_config:
                config.request_id = decrypted_config['request_id']
            if 'obfuscation' in decrypted_config:
                config.obfuscation = ObfuscationConfig(**decrypted_config['obfuscation'])
            if 'obfuscation_level' in decrypted_config:
                config.obfuscation_level = decrypted_config['obfuscation_level']
            
            logger.info(f"E2E config applied: tunnel={config.tunnel_traffic}, obf={config.obfuscation_level}")
        except Exception as e:
            logger.error(f"E2E decryption failed: {e}")
            raise HTTPException(status_code=400, detail="E2E decryption failed")
    # Plaintext mode allowed for internal testing only
    
    # Check if peer exists in memory store
    existing_config = peer_store.get(config.public_key)
    if existing_config:
        return {"status": "exists"}
    
    # Add WireGuard peer
    obfuscation_params = config.obfuscation.dict() if config.obfuscation else None
    obf_level = getattr(config, 'obfuscation_level', None) or 'off'
    
    success, assigned_ipv4, assigned_ipv6 = wg.add_peer(
        config.public_key,
        protocol=config.protocol,
        tunnel_traffic=config.tunnel_traffic,
        port=config.port,
        obfuscation=obfuscation_params,
        obfuscation_level=obf_level
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to configure WireGuard peer")

    # Prepare obfuscation parameters for storage
    obf_params = {}
    if config.obfuscation:
        obf = config.obfuscation
        obf_params = {
            'obfuscation_enabled': obf.enabled,
            'junk_packet_count': obf.jc,
            'junk_packet_min_size': obf.jmin,
            'junk_packet_max_size': obf.jmax,
            'init_packet_junk_size': obf.s1,
            'response_packet_junk_size': obf.s2,
            'underload_packet_junk_size': obf.s3,
            'transport_packet_junk_size': obf.s4,
            'init_packet_magic_header': obf.h1,
            'response_packet_magic_header': obf.h2,
            'underload_packet_magic_header': obf.h3,
            'transport_packet_magic_header': obf.h4
        }
    
    # Save to in-memory store (RAM-only mode)
    new_config = PeerConfig(
        public_key=config.public_key,
        status="active",
        assigned_ip=assigned_ipv4,
        assigned_ipv6=assigned_ipv6 or "",
        assigned_port=config.port or 0,
        tunnel_traffic=config.tunnel_traffic,
        dns_choice=config.dns or "",
        allowed_ips=','.join(wg.get_allowed_ips(config.tunnel_traffic)),
        obfuscation_level=obf_level,
        **obf_params
    )
    peer_store.add(new_config)
    
    # Broadcast FULL peer config to mesh for RAM-only recovery
    if MESH_SYNC_AVAILABLE:
        try:
            obf_level = getattr(config, 'obfuscation_level', None) or 'off'
            peer_config_for_mesh = {
                "public_key": config.public_key,
                "assigned_ip": assigned_ipv4,
                "assigned_ipv6": assigned_ipv6,
                "assigned_port": config.port,
                "tunnel_traffic": config.tunnel_traffic,
                "dns_choice": config.dns,
                "allowed_ips": wg.get_allowed_ips(config.tunnel_traffic),
                "obfuscation_level": obf_level,
                "status": "active",  # New peers start as active
                **obf_params
            }
            background_tasks.add_task(on_peer_created, peer_config_for_mesh)
            logger.debug("Queued peer config broadcast to mesh")
        except Exception as e:
            logger.warning(f"Failed to queue mesh broadcast: {e}")
    
    # Get obfuscation params and interface public key based on obfuscation_level
    from dotenv import dotenv_values
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    env_vars = dotenv_values(env_path)
    
    obf_level = getattr(config, 'obfuscation_level', None) or 'off'
    interface_map = {'off': 'wg0', 'basic': 'wg1', 'high': 'wg2', 'stealth': 'wg3'}
    target_interface = interface_map.get(obf_level, 'wg0')
    
    # Get interface public key
    interface_pubkey = env_vars.get(f"INTERFACE_{target_interface}_PUBLIC_KEY", env_vars.get("GATEWAY_PUBLIC_KEY", ""))
    
    # Get obfuscation parameters from env if level is not 'off'
    obf_response = None
    if obf_level != 'off':
        obf_response = {
            "enabled": True,
            "jc": int(env_vars.get(f"INTERFACE_{target_interface}_JC", 0)),
            "jmin": int(env_vars.get(f"INTERFACE_{target_interface}_JMIN", 0)),
            "jmax": int(env_vars.get(f"INTERFACE_{target_interface}_JMAX", 0)),
            "s1": int(env_vars.get(f"INTERFACE_{target_interface}_S1", 0)),
            "s2": int(env_vars.get(f"INTERFACE_{target_interface}_S2", 0)),
            "s3": int(env_vars.get(f"INTERFACE_{target_interface}_S3", 0) or 0),
            "s4": int(env_vars.get(f"INTERFACE_{target_interface}_S4", 0) or 0),
            "h1": int(env_vars.get(f"INTERFACE_{target_interface}_H1", 0)),
            "h2": int(env_vars.get(f"INTERFACE_{target_interface}_H2", 0)),
            "h3": int(env_vars.get(f"INTERFACE_{target_interface}_H3", 0)),
            "h4": int(env_vars.get(f"INTERFACE_{target_interface}_H4", 0)),
        }
    
    # Build response - port is the customer's assigned port (for NAT forwarding)
    response = {
        "status": "created",
        "assigned_ip": assigned_ipv4,
        "server_public_key": interface_pubkey,
        "port": config.port,  # Customer's assigned port (from port range)
        "obfuscation_level": obf_level
    }
    
    # Add obfuscation params if not 'off'
    if obf_response:
        response["obfuscation"] = obf_response
    
    # Add IPv6 address if available
    if assigned_ipv6:
        response["assigned_ipv6"] = assigned_ipv6
    
    # Encrypt response if E2E mode, otherwise plaintext (testing only)
    return encrypt_e2e_response(response, e2e_ctx)

@app.put("/api/v1/configurations/{public_key}/status")
async def update_status(
    public_key: str,
    status: ConfigStatus,
    background_tasks: BackgroundTasks,
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """Update peer status (RAM-only mode)"""
    body = json.dumps(status.dict(exclude_unset=True), sort_keys=True)
    verify_admin_request(signature, timestamp, body)
    
    # Convert URL-safe key to standard format
    standard_key = public_key.replace('_', '/').replace('-', '+')
    if standard_key.endswith('%3D'):
        standard_key = standard_key[:-3] + '='
    
    # Try to find config in memory store
    config = peer_store.get(standard_key)
    
    # If not in memory, try to recover from mesh
    if not config and MESH_SYNC_AVAILABLE and status.status == "active":
        logger.info(f"Config not in memory, querying mesh for: {standard_key[:20]}...")
        try:
            mesh_config = await query_suspended_peer(standard_key)
            if mesh_config:
                logger.info(f"Found peer config in mesh, adding to memory store")
                config = PeerConfig(
                    public_key=standard_key,
                    status="suspended",
                    assigned_ip=mesh_config.get("assigned_ip", ""),
                    assigned_ipv6=mesh_config.get("assigned_ipv6", ""),
                    assigned_port=mesh_config.get("assigned_port", 0),
                    tunnel_traffic=mesh_config.get("tunnel_traffic", "all"),
                    dns_choice=mesh_config.get("dns_choice", ""),
                    allowed_ips=mesh_config.get("allowed_ips", ""),
                    obfuscation_level=mesh_config.get("obfuscation_level", "off"),
                    obfuscation_enabled=mesh_config.get("obfuscation_enabled", False),
                    junk_packet_count=mesh_config.get("junk_packet_count", 0),
                    junk_packet_min_size=mesh_config.get("junk_packet_min_size", 0),
                    junk_packet_max_size=mesh_config.get("junk_packet_max_size", 0),
                    init_packet_junk_size=mesh_config.get("init_packet_junk_size", 0),
                    response_packet_junk_size=mesh_config.get("response_packet_junk_size", 0),
                    underload_packet_junk_size=mesh_config.get("underload_packet_junk_size", 0),
                    transport_packet_junk_size=mesh_config.get("transport_packet_junk_size", 0),
                    init_packet_magic_header=mesh_config.get("init_packet_magic_header", 0),
                    response_packet_magic_header=mesh_config.get("response_packet_magic_header", 0),
                    underload_packet_magic_header=mesh_config.get("underload_packet_magic_header", 0),
                    transport_packet_magic_header=mesh_config.get("transport_packet_magic_header", 0)
                )
                peer_store.add(config)
        except Exception as e:
            logger.warning(f"Failed to recover config from mesh: {e}")
    
    if not config:
        logger.error(f"Config not found for key: {standard_key}")
        raise HTTPException(status_code=404, detail="Configuration not found")
    
    standard_key = config.public_key

    if status.status == "suspended":
        # Remove from WireGuard immediately
        wg.remove_peer(standard_key)
        
        # Update memory store status
        peer_store.update(standard_key, status="suspended")
        
        # Queue mesh status update
        if MESH_SYNC_AVAILABLE:
            background_tasks.add_task(mesh_suspend_task, standard_key)
        
        logger.info(f"Suspended peer: {standard_key[:20]}...")
        return {"status": "suspended"}
    
    elif status.status == "active":
        if not wg.verify_peer_exists(standard_key):
            # Determine obfuscation level from config or IP subnet
            obf_level = config.obfuscation_level or 'off'
            if obf_level == 'off' and config.assigned_ip:
                ip_parts = config.assigned_ip.split('.')
                if len(ip_parts) >= 3:
                    subnet_id = ip_parts[2]
                    subnet_map = {'30': 'off', '31': 'basic', '32': 'high', '33': 'stealth'}
                    obf_level = subnet_map.get(subnet_id, 'off')
            logger.info(f"Resuming peer with obfuscation level '{obf_level}'")
            
            success, _, _ = wg.add_peer(
                standard_key,
                protocol='dual' if config.assigned_ipv6 else None,
                tunnel_traffic=config.tunnel_traffic,
                port=config.assigned_port,
                assigned_ipv4=config.assigned_ip,
                assigned_ipv6=config.assigned_ipv6,
                obfuscation_level=obf_level
            )
            if not success:
                raise HTTPException(status_code=500, detail="Failed to activate peer")
        
        # Update memory store status
        peer_store.update(standard_key, status="active")
        
        # Queue mesh status update
        if MESH_SYNC_AVAILABLE:
            background_tasks.add_task(mesh_resume_task, standard_key)
    
    return {"status": "updated"}

@app.delete("/api/v1/configurations/{public_key}")
async def delete_configuration(
    public_key: str,
    background_tasks: BackgroundTasks,
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """Delete peer (RAM-only mode)"""
    # Verify HMAC signature (empty body for DELETE)
    verify_admin_request(signature, timestamp)
    
    standard_key = public_key.replace('_', '/').replace('-', '+')
    if standard_key.endswith('%3D'):
        standard_key = standard_key[:-3] + '='
    
    logger.info(f"Delete request for key: {standard_key[:20]}...")
    
    # Find config in memory store
    config = peer_store.get(standard_key)
    if not config:
        logger.warning(f"Config not found in peer_store for key: {standard_key[:20]}...")
        # Still try to remove from WireGuard and mesh in case it exists there
        wg.remove_peer(standard_key)
        if MESH_SYNC_AVAILABLE:
            background_tasks.add_task(on_peer_deleted, standard_key)
        raise HTTPException(status_code=404, detail="Configuration not found")
    
    standard_key = config.public_key
    
    # Remove from WireGuard
    wg.remove_peer(standard_key)
    
    # Delete from memory store
    peer_store.delete(standard_key)
    
    # Broadcast peer deletion to mesh
    if MESH_SYNC_AVAILABLE:
        try:
            background_tasks.add_task(on_peer_deleted, standard_key)
            logger.debug("Queued peer deletion broadcast to mesh")
        except Exception as e:
            logger.warning(f"Failed to queue mesh deletion broadcast: {e}")
    
    logger.info(f"Deleted peer: {standard_key}")
    return {"status": "deleted"}

@app.get("/api/v1/ip-usage")
async def get_ip_usage(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    verify_admin_request(signature, timestamp)
    return wg.get_ip_usage()

@app.post("/api/v1/sync-ips")
async def sync_ips(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    verify_admin_request(signature, timestamp)
    wg.sync_assigned_ips()
    return {"status": "synced"}


# ... adding this form Admin monitoring ...
@app.get("/api/v1/server/status")
async def server_status(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    verify_admin_request(signature, timestamp)
    
    try:
        # Get system metrics
        memory = psutil.virtual_memory()
        load = psutil.getloadavg()
        
        # Get WireGuard metrics
        active_peers = wg.get_active_peer_count()
        total_peers = wg.get_total_peer_count()
        
        status_data = {
            "wireguard_peers": active_peers,
            "total_peers": total_peers,  # Added total configured peers
            "memory_usage": memory.percent,
            "load_average": load[0],  # 1-minute load average
            "timestamp": datetime.now().isoformat(),
            "status": "healthy"
        }
        
        logger.info(f"Status check: {status_data}")
        return status_data
        
    except Exception as e:
        logger.error(f"Status check failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get server status: {str(e)}"
        )

# Optional: Add detailed metrics endpoint
@app.get("/api/v1/server/metrics")
async def server_metrics(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    verify_admin_request(signature, timestamp)

    try:
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return {
            "system": {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": disk.percent
                },
                "load_average": psutil.getloadavg()
            },
            "wireguard": {
                "active_peers": wg.get_active_peer_count(),
                "total_peers": wg.get_total_peer_count(),
                "ip_usage": wg.get_ip_usage(),
                "last_handshakes": wg.get_peer_handshakes()
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Metrics collection failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to collect metrics: {str(e)}"
        )


# ============================================================================
# ADMIN METRICS ENDPOINTS - Privacy-preserving statistics (no identifiable data)
# ============================================================================

@app.get("/api/v1/admin/interface-stats")
async def get_interface_stats(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Get per-interface statistics - privacy preserving (no identifiable data).
    Returns counts only, no public keys or IP addresses.
    """
    verify_admin_request(signature, timestamp)
    
    try:
        interfaces = ['wg0', 'wg1', 'wg2', 'wg3']
        interface_labels = {
            'wg0': 'Standard (No Obfuscation)',
            'wg1': 'Basic Obfuscation', 
            'wg2': 'High Obfuscation',
            'wg3': 'Stealth Mode'
        }
        
        stats = {}
        for iface in interfaces:
            try:
                # Get peer count from WireGuard
                result = subprocess.run(
                    ["/usr/bin/sudo", "/usr/bin/awg", "show", iface, "peers"],
                    capture_output=True, text=True, timeout=5
                )
                wg_peer_count = len([p for p in result.stdout.strip().split('\n') if p.strip()]) if result.returncode == 0 else 0
                
                # Get active peers (those with recent handshake)
                result = subprocess.run(
                    ["/usr/bin/sudo", "/usr/bin/awg", "show", iface],
                    capture_output=True, text=True, timeout=5
                )
                active_count = 0
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if 'latest handshake:' in line.lower():
                            handshake_time = line.split(':', 1)[1].strip() if ':' in line else ''
                            if handshake_time and 'never' not in handshake_time.lower():
                                active_count += 1
                
                stats[iface] = {
                    "label": interface_labels.get(iface, iface),
                    "total_peers": wg_peer_count,
                    "active_peers": active_count,
                    "inactive_peers": wg_peer_count - active_count
                }
            except subprocess.TimeoutExpired:
                stats[iface] = {"label": interface_labels.get(iface, iface), "error": "timeout"}
            except Exception as e:
                stats[iface] = {"label": interface_labels.get(iface, iface), "error": str(e)}
        
        # Get counts from in-memory store (RAM-only mode)
        store_stats = peer_store.stats()
        
        return {
            "interfaces": stats,
            "peer_store": {
                "total_configurations": store_stats["total_peers"],
                "active_configurations": store_stats["active_peers"],
                "suspended_configurations": store_stats["suspended_peers"]
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Interface stats collection failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to collect interface stats: {str(e)}")


@app.get("/api/v1/admin/health")
async def get_health_status(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Get comprehensive health and uptime data - privacy preserving.
    """
    verify_admin_request(signature, timestamp)
    
    try:
        # System uptime
        uptime_seconds = psutil.boot_time()
        uptime_since = datetime.fromtimestamp(uptime_seconds)
        current_time = datetime.now()
        uptime_delta = current_time - uptime_since
        
        # Format uptime as human readable
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"
        
        # CPU info
        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_count = psutil.cpu_count()
        load_avg = psutil.getloadavg()
        
        # Memory info
        memory = psutil.virtual_memory()
        
        # Disk info
        disk = psutil.disk_usage('/')
        
        # Network info (traffic stats - no IPs)
        net_io = psutil.net_io_counters()
        
        # WireGuard interface status
        wg_status = {}
        for iface in ['wg0', 'wg1', 'wg2', 'wg3']:
            try:
                result = subprocess.run(
                    ["/usr/sbin/ip", "link", "show", iface],
                    capture_output=True, text=True, timeout=3
                )
                wg_status[iface] = "up" if result.returncode == 0 and "UP" in result.stdout else "down"
            except:
                wg_status[iface] = "unknown"
        
        # Process status
        wg_manager_running = any("uvicorn" in p.name().lower() or "wg-manager" in p.name().lower() 
                                  for p in psutil.process_iter(['name']))
        
        # Determine overall health status
        health_issues = []
        if cpu_percent > 90:
            health_issues.append("high_cpu")
        if memory.percent > 90:
            health_issues.append("high_memory")
        if disk.percent > 90:
            health_issues.append("low_disk_space")
        if load_avg[0] > cpu_count * 2:
            health_issues.append("high_load")
        if any(s == "down" for s in wg_status.values()):
            health_issues.append("interface_down")
        
        overall_status = "healthy" if not health_issues else "degraded" if len(health_issues) < 3 else "critical"
        
        return {
            "status": overall_status,
            "health_issues": health_issues,
            "uptime": {
                "boot_time": uptime_since.isoformat(),
                "uptime_seconds": int(uptime_delta.total_seconds()),
                "uptime_human": uptime_str
            },
            "cpu": {
                "percent": cpu_percent,
                "count": cpu_count,
                "load_average": {
                    "1min": round(load_avg[0], 2),
                    "5min": round(load_avg[1], 2),
                    "15min": round(load_avg[2], 2)
                }
            },
            "memory": {
                "total_gb": round(memory.total / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "percent_used": memory.percent
            },
            "disk": {
                "total_gb": round(disk.total / (1024**3), 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "percent_used": disk.percent
            },
            "network": {
                "bytes_sent_gb": round(net_io.bytes_sent / (1024**3), 2),
                "bytes_recv_gb": round(net_io.bytes_recv / (1024**3), 2),
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv
            },
            "wireguard_interfaces": wg_status,
            "services": {
                "wg_manager_api": "running" if wg_manager_running else "stopped"
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get health status: {str(e)}")


@app.get("/api/v1/admin/health/dns")
async def get_dns_health(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Get DNS server health status.
    Checks if Unbound DNS service is running and can resolve queries.
    """
    verify_admin_request(signature, timestamp)
    
    try:
        import time
        
        # Check if unbound-d1 service is active
        # NOTE: Use full paths for subprocess - systemd services have limited PATH
        service_active = False
        try:
            result = subprocess.run(
                ["/usr/bin/systemctl", "is-active", "unbound-d1"],
                capture_output=True, text=True, timeout=5
            )
            service_active = result.returncode == 0 and result.stdout.strip() == "active"
        except Exception as e:
            logger.debug(f"Failed to check unbound-d1 service: {e}")
        
        # Measure DNS query latency (if service is active)
        query_latency_ms = 0
        upstream_reachable = False
        
        if service_active:
            try:
                start_time = time.time()
                result = subprocess.run(
                    ["/usr/bin/dig", "@10.65.1.1", "google.com", "+short", "+timeout=3"],
                    capture_output=True, text=True, timeout=5
                )
                end_time = time.time()
                
                if result.returncode == 0 and result.stdout.strip():
                    query_latency_ms = int((end_time - start_time) * 1000)
                    upstream_reachable = True
            except Exception as e:
                logger.debug(f"DNS query test failed: {e}")
        
        # Determine overall DNS status
        if not service_active:
            dns_status = "not_deployed"
        elif not upstream_reachable:
            dns_status = "down"
        elif query_latency_ms > 100:
            dns_status = "slow"
        else:
            dns_status = "ok"
        
        return {
            "dns_service_active": service_active,
            "dns_query_latency_ms": query_latency_ms,
            "dns_upstream_reachable": upstream_reachable,
            "dns_status": dns_status,
            "dns_last_check": datetime.now().isoformat(),
            "dns_server_ip": "10.65.1.1" if service_active else None,
            "dns_upstream": "9.9.9.9" if service_active else None
        }
        
    except Exception as e:
        logger.error(f"DNS health check failed: {str(e)}")
        return {
            "dns_service_active": False,
            "dns_query_latency_ms": 0,
            "dns_upstream_reachable": False,
            "dns_status": "error",
            "dns_last_check": datetime.now().isoformat(),
            "error": str(e)
        }


@app.get("/api/v1/admin/health/dns/{level}")
async def get_dns_health_by_level(
    level: str,
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Get DNS server health status for a specific level (d1, d2, d3).
    """
    verify_admin_request(signature, timestamp)
    
    # DNS configuration by level
    dns_config = {
        "d1": {"ip": "10.65.1.1", "name": "Clean", "service": "unbound-d1"},
        "d2": {"ip": "10.65.1.2", "name": "Ad-Block", "service": "unbound-d2"},
        "d3": {"ip": "10.65.1.3", "name": "Maximum", "service": "unbound-d3"},
    }
    
    if level not in dns_config:
        return {"error": f"Unknown DNS level: {level}", "valid_levels": list(dns_config.keys())}
    
    config = dns_config[level]
    
    try:
        import time
        
        # Check if service is active
        service_active = False
        try:
            result = subprocess.run(
                ["/usr/bin/systemctl", "is-active", config["service"]],
                capture_output=True, text=True, timeout=5
            )
            service_active = result.returncode == 0 and result.stdout.strip() == "active"
        except Exception as e:
            logger.debug(f"Failed to check {config['service']} service: {e}")
        
        # Measure DNS query latency
        query_latency_ms = 0
        upstream_reachable = False
        blocked_domains = 0
        blocklist_version = None
        
        if service_active:
            try:
                start_time = time.time()
                result = subprocess.run(
                    ["/usr/bin/dig", f"@{config['ip']}", "google.com", "+short", "+timeout=3"],
                    capture_output=True, text=True, timeout=5
                )
                end_time = time.time()
                
                if result.returncode == 0 and result.stdout.strip():
                    query_latency_ms = int((end_time - start_time) * 1000)
                    upstream_reachable = True
            except Exception as e:
                logger.debug(f"DNS query test failed for {level}: {e}")
            
            # For d2/d3, check blocklist info
            if level in ["d2", "d3"]:
                try:
                    blocklist_path = f"/dev/shm/dns/blocklist-{level}.conf"
                    result = subprocess.run(
                        ["/usr/bin/wc", "-l", blocklist_path],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        # Each line is a local-zone entry (minus header)
                        blocked_domains = max(0, int(result.stdout.split()[0]) - 10)
                    
                    # Try to read version from config comment
                    result = subprocess.run(
                        ["/usr/bin/head", "-5", blocklist_path],
                        capture_output=True, text=True, timeout=5
                    )
                    if "Generated:" in result.stdout:
                        for line in result.stdout.split('\n'):
                            if "Generated:" in line:
                                blocklist_version = line.split("Generated:")[1].strip()
                                break
                except Exception as e:
                    logger.debug(f"Failed to get blocklist info for {level}: {e}")
        
        # Determine status
        if not service_active:
            dns_status = "not_deployed"
        elif not upstream_reachable:
            dns_status = "down"
        elif query_latency_ms > 100:
            dns_status = "slow"
        else:
            dns_status = "ok"
        
        response = {
            "level": level,
            "name": config["name"],
            "dns_service_active": service_active,
            "dns_query_latency_ms": query_latency_ms,
            "dns_upstream_reachable": upstream_reachable,
            "dns_status": dns_status,
            "dns_server_ip": config["ip"] if service_active else None,
            "dns_last_check": datetime.now().isoformat()
        }
        
        # Add blocklist info for d2/d3
        if level in ["d2", "d3"]:
            response["blocked_domains"] = blocked_domains
            response["blocklist_version"] = blocklist_version
        
        return response
        
    except Exception as e:
        logger.error(f"DNS health check failed for {level}: {str(e)}")
        return {
            "level": level,
            "dns_service_active": False,
            "dns_status": "error",
            "dns_last_check": datetime.now().isoformat(),
            "error": str(e)
        }


@app.get("/api/v1/admin/health/dns/all")
async def get_all_dns_health(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Get health status for all DNS levels (d1, d2, d3).
    """
    verify_admin_request(signature, timestamp)
    
    results = {}
    for level in ["d1", "d2", "d3"]:
        # Reuse the level-specific function logic
        dns_config = {
            "d1": {"ip": "10.65.1.1", "name": "Clean", "service": "unbound-d1"},
            "d2": {"ip": "10.65.1.2", "name": "Ad-Block", "service": "unbound-d2"},
            "d3": {"ip": "10.65.1.3", "name": "Maximum", "service": "unbound-d3"},
        }
        config = dns_config[level]
        
        service_active = False
        try:
            result = subprocess.run(
                ["/usr/bin/systemctl", "is-active", config["service"]],
                capture_output=True, text=True, timeout=5
            )
            service_active = result.returncode == 0 and result.stdout.strip() == "active"
        except:
            pass
        
        results[level] = {
            "name": config["name"],
            "ip": config["ip"],
            "active": service_active,
            "status": "ok" if service_active else "not_deployed"
        }
    
    return {
        "dns_levels": results,
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/v1/admin/recover-peers")
async def recover_peers_from_mesh(
    background_tasks: BackgroundTasks,
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Recover peer configurations from the mesh (RAM-only mode).
    This is now handled automatically on startup, but can be called manually.
    """
    verify_admin_request(signature, timestamp)
    
    if not MESH_SYNC_AVAILABLE:
        return {
            "status": "unavailable",
            "message": "Mesh peer sync not available on this gateway",
            "recovered_count": 0
        }
    
    try:
        result = await recover_peers()
        
        if result.success:
            restored_count = 0
            for peer_config in result.recovered_configs:
                try:
                    if peer_config.get("_deleted"):
                        continue
                    
                    public_key = peer_config.get("public_key")
                    if not public_key:
                        continue
                    
                    # Check if already exists in memory
                    if peer_store.exists(public_key):
                        logger.debug(f"Peer already in memory: {public_key[:16]}...")
                        continue
                    
                    # Get obfuscation level
                    assigned_ip = peer_config.get("assigned_ip", "")
                    obf_level = peer_config.get("obfuscation_level", None)
                    if not obf_level and assigned_ip:
                        ip_parts = assigned_ip.split('.')
                        if len(ip_parts) >= 3:
                            subnet_map = {'30': 'off', '31': 'basic', '32': 'high', '33': 'stealth'}
                            obf_level = subnet_map.get(ip_parts[2], 'off')
                    obf_level = obf_level or 'off'
                    
                    peer_status = peer_config.get("status", "active")
                    
                    # Create PeerConfig for memory store
                    allowed_ips = peer_config.get("allowed_ips", "")
                    if isinstance(allowed_ips, list):
                        allowed_ips = ','.join(allowed_ips)
                    
                    new_config = PeerConfig(
                        public_key=public_key,
                        status=peer_status,
                        assigned_ip=assigned_ip,
                        assigned_ipv6=peer_config.get("assigned_ipv6", ""),
                        assigned_port=peer_config.get("assigned_port", 0),
                        tunnel_traffic=peer_config.get("tunnel_traffic", "all"),
                        dns_choice=peer_config.get("dns_choice", ""),
                        allowed_ips=allowed_ips,
                        obfuscation_level=obf_level,
                        obfuscation_enabled=peer_config.get("obfuscation_enabled", False),
                        junk_packet_count=peer_config.get("junk_packet_count", 0),
                        junk_packet_min_size=peer_config.get("junk_packet_min_size", 0),
                        junk_packet_max_size=peer_config.get("junk_packet_max_size", 0),
                        init_packet_junk_size=peer_config.get("init_packet_junk_size", 0),
                        response_packet_junk_size=peer_config.get("response_packet_junk_size", 0),
                        underload_packet_junk_size=peer_config.get("underload_packet_junk_size", 0),
                        transport_packet_junk_size=peer_config.get("transport_packet_junk_size", 0),
                        init_packet_magic_header=peer_config.get("init_packet_magic_header", 0),
                        response_packet_magic_header=peer_config.get("response_packet_magic_header", 0),
                        underload_packet_magic_header=peer_config.get("underload_packet_magic_header", 0),
                        transport_packet_magic_header=peer_config.get("transport_packet_magic_header", 0)
                    )
                    
                    # Add to memory store
                    peer_store.add(new_config)
                    
                    # Only add active peers to WireGuard
                    if peer_status == "active":
                        success, _, _ = wg.add_peer(
                            public_key,
                            protocol='dual' if peer_config.get("assigned_ipv6") else None,
                            tunnel_traffic=peer_config.get("tunnel_traffic", "all"),
                            port=peer_config.get("assigned_port"),
                            assigned_ipv4=assigned_ip,
                            assigned_ipv6=peer_config.get("assigned_ipv6"),
                            obfuscation_level=obf_level
                        )
                        if success:
                            logger.info(f"Recovered active peer: {public_key[:16]}...")
                        else:
                            logger.warning(f"Failed to add recovered peer to WireGuard: {public_key[:16]}...")
                    else:
                        logger.info(f"Recovered suspended peer: {public_key[:16]}... (not adding to WireGuard)")
                    
                    restored_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to restore peer: {e}")
            
            return {
                "status": "success",
                "recovered_count": restored_count,
                "total_in_mesh": len(result.recovered_configs),
                "quorum_achieved": result.quorum.achieved,
                "agreeing_peers": len(result.quorum.agreeing_peers),
                "identity": result.identity_pubkey[:16] + "...",
                "message": result.message
            }
        else:
            return {
                "status": "failed",
                "recovered_count": 0,
                "quorum_achieved": result.quorum.achieved,
                "errors": result.quorum.errors,
                "message": result.message
            }
            
    except Exception as e:
        logger.error(f"Peer recovery failed: {e}")
        raise HTTPException(status_code=500, detail=f"Peer recovery failed: {str(e)}")


@app.post("/api/v1/admin/reconcile-peers")
async def reconcile_peers_admin(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Reconcile peers from mesh and apply to WireGuard immediately.
    This is a manual "reconcile now" action for online gateways.
    """
    verify_admin_request(signature, timestamp)

    if not MESH_SYNC_AVAILABLE:
        return {
            "status": "unavailable",
            "message": "Mesh peer sync not available on this gateway"
        }

    return await reconcile_peers_from_mesh()


@app.post("/api/v1/admin/reboot")
async def reboot_gateway(
    background_tasks: BackgroundTasks,
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Schedule a gateway reboot. Requires admin authentication.
    The reboot is scheduled with a 5-second delay to allow the API response.
    """
    verify_admin_request(signature, timestamp)
    
    def perform_reboot():
        import time
        time.sleep(5)  # Wait 5 seconds before rebooting
        subprocess.run(["/usr/bin/sudo", "/sbin/reboot"], check=False)
    
    background_tasks.add_task(perform_reboot)
    logger.warning("REBOOT SCHEDULED - Gateway will restart in 5 seconds")
    
    return {
        "status": "reboot_scheduled",
        "message": "Gateway will reboot in 5 seconds",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/v1/admin/restart-wireguard")
async def restart_wireguard(
    background_tasks: BackgroundTasks,
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Restart all WireGuard interfaces without full system reboot.
    """
    verify_admin_request(signature, timestamp)
    
    results = {}
    for iface in ['wg0', 'wg1', 'wg2', 'wg3']:
        try:
            # Restart interface
            subprocess.run(["/usr/bin/sudo", "/usr/bin/awg-quick", "down", iface], capture_output=True, timeout=10)
            subprocess.run(["/usr/bin/sudo", "/usr/bin/awg-quick", "up", iface], capture_output=True, timeout=10)
            results[iface] = "restarted"
            logger.info(f"Restarted WireGuard interface: {iface}")
        except subprocess.TimeoutExpired:
            results[iface] = "timeout"
            logger.error(f"Timeout restarting interface: {iface}")
        except Exception as e:
            results[iface] = f"error: {str(e)}"
            logger.error(f"Failed to restart interface {iface}: {e}")
    
    # Reconstruct peers after restart
    try:
        wg.sync_and_reconstruct_peers()
        results["peer_reconstruction"] = "success"
    except Exception as e:
        results["peer_reconstruction"] = f"error: {str(e)}"
    
    return {
        "status": "completed",
        "interfaces": results,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/v1/admin/crl-status")
async def get_crl_enforcement_status(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Get CRL enforcement status for this gateway.
    Shows whether certificate revocation is being enforced.
    """
    verify_admin_request(signature, timestamp)
    
    # Refresh CRL before returning status
    refresh_crl_cache()
    status = get_crl_status()
    
    return {
        "enforcement_active": status["enforcement_active"],
        "crl_version": status["version"],
        "revoked_count": status["entries_count"],
        "loaded_at": status["loaded_at"],
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/v1/admin/crl-check")
async def check_certificate_revocation(
    serial_number: str,
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Check if a specific certificate serial is revoked.
    Used by backend to verify gateway certificates.
    """
    verify_admin_request(signature, timestamp)
    
    # Refresh CRL before checking
    refresh_crl_cache()
    revoked = is_certificate_revoked(serial_number)
    
    return {
        "serial_number": serial_number,
        "is_revoked": revoked,
        "crl_version": get_crl_status()["version"],
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/v1/admin/summary")
async def get_admin_summary(
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    """
    Quick summary endpoint for dashboard - privacy preserving aggregate stats only.
    RAM-only mode: uses in-memory peer store.
    """
    verify_admin_request(signature, timestamp)
    
    try:
        # Get uptime
        uptime_seconds = psutil.boot_time()
        uptime_since = datetime.fromtimestamp(uptime_seconds)
        uptime_delta = datetime.now() - uptime_since
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        uptime_str = f"{days}d {hours}h"
        
        # System stats
        memory = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Total peer counts across all interfaces
        total_wg_peers = 0
        total_active_peers = 0
        for iface in ['wg0', 'wg1', 'wg2', 'wg3']:
            try:
                result = subprocess.run(
                    ["/usr/bin/sudo", "/usr/bin/awg", "show", iface, "peers"],
                    capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    peers = [p for p in result.stdout.strip().split('\n') if p.strip()]
                    total_wg_peers += len(peers)
                
                result = subprocess.run(
                    ["/usr/bin/sudo", "/usr/bin/awg", "show", iface],
                    capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if 'latest handshake:' in line.lower():
                            if 'never' not in line.lower():
                                total_active_peers += 1
            except:
                pass
        
        # Get stats from in-memory peer store (RAM-only mode)
        store_stats = peer_store.stats()
        
        return {
            "uptime": uptime_str,
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "total_peers_wireguard": total_wg_peers,
            "active_peers_connected": total_active_peers,
            "total_configurations": store_stats["total_peers"],
            "active_configurations": store_stats["active_peers"],
            "suspended_configurations": store_stats["suspended_peers"],
            "status": "healthy" if cpu_percent < 80 and memory.percent < 80 else "degraded",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Summary collection failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get summary: {str(e)}")


# =============================================================================
# Admin Lifecycle Endpoints (for backend orchestration)
# =============================================================================

@app.post("/admin/service/{service_name}/stop")
async def stop_service(
    service_name: str,
    signature: str = Header(...),
    timestamp: str = Header(...),
    x_nonce: str = Header(None, alias="X-Nonce")  # Optional nonce for replay protection
):
    """Stop a systemd service (admin only, HMAC authenticated)"""
    # Validate service name
    allowed_services = ["wg-manager", "whisper-node"]
    if service_name not in allowed_services:
        raise HTTPException(status_code=400, detail=f"Invalid service: {service_name}")
    
    # Verify HMAC with optional nonce for replay protection
    # Body includes service_name to bind the action
    body = json.dumps({"service": service_name, "action": "stop"})
    verify_admin_request(signature, timestamp, body, nonce=x_nonce)
    
    # Stop the service
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "/usr/bin/systemctl", "stop", service_name],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            logger.error(f"Failed to stop {service_name}: {result.stderr}")
            raise HTTPException(status_code=500, detail=f"Failed to stop {service_name}")
        
        logger.info(f"Service {service_name} stopped by admin request")
        return {"status": "stopped", "service": service_name}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Service stop timed out")


@app.post("/admin/service/{service_name}/start")
async def start_service(
    service_name: str,
    signature: str = Header(...),
    timestamp: str = Header(...),
    x_nonce: str = Header(None, alias="X-Nonce")  # Optional nonce for replay protection
):
    """Start a systemd service (admin only, HMAC authenticated)"""
    # Validate service name
    allowed_services = ["wg-manager", "whisper-node"]
    if service_name not in allowed_services:
        raise HTTPException(status_code=400, detail=f"Invalid service: {service_name}")
    
    # Verify HMAC with optional nonce for replay protection
    body = json.dumps({"service": service_name, "action": "start"})
    verify_admin_request(signature, timestamp, body, nonce=x_nonce)
    
    # Start the service
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "/usr/bin/systemctl", "start", service_name],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            logger.error(f"Failed to start {service_name}: {result.stderr}")
            raise HTTPException(status_code=500, detail=f"Failed to start {service_name}")
        
        logger.info(f"Service {service_name} started by admin request")
        return {"status": "started", "service": service_name}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Service start timed out")


@app.post("/admin/wipe")
async def wipe_gateway(
    signature: str = Header(...),
    timestamp: str = Header(...),
    x_nonce: str = Header(None, alias="X-Nonce")  # Optional nonce for replay protection
):
    """
    Complete wipe of gateway ecosystem data.
    This endpoint:
    1. Stops all WireGuard interfaces (wg0-wg3)
    2. Removes WireGuard configs
    3. Removes management tunnel (wg_mgmt)
    4. Deletes all ecosystem files
    5. Re-enables public SSH access
    6. Schedules a reboot
    
    WARNING: This is destructive and cannot be undone!
    """
    # Verify HMAC with optional nonce for replay protection
    # Include action identifier in body to prevent replay for different actions
    body = json.dumps({"action": "wipe", "confirm": True})
    verify_admin_request(signature, timestamp, body, nonce=x_nonce)
    
    logger.warning("⚠️ WIPE COMMAND RECEIVED - Beginning gateway wipe...")
    
    wipe_script = """#!/bin/bash
    set -e
    
    echo "=== Gateway Wipe Started ==="
    echo "Timestamp: $(date)"
    
    # Step 1: Stop services
    echo "[1/6] Stopping services..."
    systemctl stop wg-manager 2>/dev/null || true
    systemctl stop whisper-node 2>/dev/null || true
    systemctl disable wg-manager 2>/dev/null || true
    systemctl disable whisper-node 2>/dev/null || true
    
    # Step 2: Remove WireGuard interfaces
    echo "[2/6] Removing WireGuard interfaces..."
    for iface in wg0 wg1 wg2 wg3 wg_mgmt; do
        awg-quick down $iface 2>/dev/null || true
        rm -f /etc/amnezia/amneziawg/${iface}.conf 2>/dev/null || true
        rm -f /etc/amnezia/amneziawg/${iface}.pub 2>/dev/null || true
        rm -f /etc/amnezia/amneziawg/${iface}.key 2>/dev/null || true
    done
    rm -f /etc/wireguard/wg_mgmt.conf 2>/dev/null || true
    
    # Step 3: Remove ecosystem files
    echo "[3/6] Removing ecosystem files..."
    rm -rf /home/ubuntu/wg-manager 2>/dev/null || true
    rm -rf /home/ubuntu/whisper-node 2>/dev/null || true
    rm -f /etc/systemd/system/wg-manager.service 2>/dev/null || true
    rm -f /etc/systemd/system/whisper-node.service 2>/dev/null || true
    systemctl daemon-reload
    
    # Step 4: Re-enable public SSH
    echo "[4/6] Re-enabling public SSH access..."
    ufw delete allow in on wg_mgmt to any port 22 proto tcp 2>/dev/null || true
    ufw allow 22/tcp
    ufw reload
    
    # Step 5: Clear any remaining certs
    echo "[5/6] Clearing certificates..."
    rm -f /home/ubuntu/*.pem 2>/dev/null || true
    rm -f /home/ubuntu/*.crt 2>/dev/null || true
    rm -f /home/ubuntu/*.key 2>/dev/null || true
    
    # Step 6: Schedule reboot
    echo "[6/6] Scheduling reboot in 10 seconds..."
    echo "=== Gateway Wipe Complete ==="
    
    # Use at or nohup to schedule reboot after this script exits
    (sleep 10 && reboot) &
    """
    
    try:
        # Execute wipe script
        result = subprocess.run(
            ["/usr/bin/sudo", "/bin/bash", "-c", wipe_script],
            capture_output=True, text=True, timeout=60
        )
        
        logger.warning(f"Wipe script output: {result.stdout}")
        if result.stderr:
            logger.warning(f"Wipe script stderr: {result.stderr}")
        
        return {
            "status": "accepted",
            "message": "Gateway wipe initiated. Server will reboot in ~10 seconds.",
            "output": result.stdout
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "message": "Wipe script timed out but may still complete"
        }
    except Exception as e:
        logger.error(f"Wipe failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Wipe failed: {str(e)}")


# ============================================================================
# ANONYMOUS DNS USAGE STATS (with Lap feature)
# ============================================================================

# In-memory lap storage (resets on gateway API restart)
dns_laps: list[dict] = []
MAX_LAPS = 20  # Keep last 20 laps


def parse_unbound_stats(output: str) -> dict:
    """Parse unbound-control stats output into a dict"""
    stats = {}
    for line in output.strip().split('\n'):
        if '=' in line:
            key, value = line.split('=', 1)
            try:
                # Try to parse as number
                if '.' in value:
                    stats[key] = float(value)
                else:
                    stats[key] = int(value)
            except ValueError:
                stats[key] = value
    return stats


def get_unbound_stats(level: str) -> dict:
    """Get stats from unbound-control for a specific level"""
    port_map = {"d1": 8941, "d2": 8942, "d3": 8943}
    port = port_map.get(level, 8941)
    
    try:
        result = subprocess.run(
            ["/usr/sbin/unbound-control", "-s", f"127.0.0.1@{port}", "stats_noreset"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return parse_unbound_stats(result.stdout)
    except Exception as e:
        logger.debug(f"Error getting unbound stats for {level}: {e}")
    return {}


@app.get("/api/v1/dns/stats")
async def get_dns_stats():
    """
    Anonymous DNS usage statistics.
    Returns only aggregate counts - no user data, IPs, or identifiable info.
    """
    dns_levels = {
        "d1": {"ip": "10.65.1.1", "name": "Clean", "port": 8941},
        "d2": {"ip": "10.65.1.2", "name": "Ad-Block", "port": 8942},
        "d3": {"ip": "10.65.1.3", "name": "Maximum", "port": 8943},
    }
    
    stats = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "gateway": os.getenv("GATEWAY_NAME", "unknown"),
        "levels": {}
    }
    
    total_queries = 0
    total_blocked = 0
    total_cache_hits = 0
    total_cache_miss = 0
    
    for level, config in dns_levels.items():
        level_stats = {
            "name": config["name"],
            "ip": config["ip"],
            "active": False,
            "queries": 0,
            "cache_hits": 0,
            "cache_miss": 0,
            "blocked": 0,
            "avg_response_ms": 0,
        }
        
        try:
            # Check if service is active
            result = subprocess.run(
                ["/usr/bin/systemctl", "is-active", f"unbound-{level}"],
                capture_output=True, text=True, timeout=3
            )
            level_stats["active"] = result.returncode == 0
            
            if level_stats["active"]:
                # Get detailed stats from unbound-control
                unbound_stats = get_unbound_stats(level)
                
                if unbound_stats:
                    # Aggregate thread stats
                    queries = unbound_stats.get("total.num.queries", 0)
                    cache_hits = unbound_stats.get("total.num.cachehits", 0)
                    cache_miss = unbound_stats.get("total.num.cachemiss", 0)
                    
                    # For blocked queries, count NXDOMAIN responses (blocked domains return NXDOMAIN)
                    # In Unbound with local-zone static, blocked = queries that hit blocklist
                    nxdomain = unbound_stats.get("num.answer.rcode.NXDOMAIN", 0)
                    
                    # Average response time (recursion time in seconds -> ms)
                    avg_time = unbound_stats.get("total.recursion.time.avg", 0)
                    
                    level_stats["queries"] = queries
                    level_stats["cache_hits"] = cache_hits
                    level_stats["cache_miss"] = cache_miss
                    level_stats["blocked"] = nxdomain if level != "d1" else 0  # d1 has no blocklist
                    level_stats["avg_response_ms"] = round(avg_time * 1000, 2)
                    
                    # Calculate cache hit rate
                    if queries > 0:
                        level_stats["cache_hit_rate"] = round((cache_hits / queries) * 100, 1)
                    else:
                        level_stats["cache_hit_rate"] = 0
                    
                    total_queries += queries
                    total_cache_hits += cache_hits
                    total_cache_miss += cache_miss
                    if level != "d1":
                        total_blocked += nxdomain
                
        except Exception as e:
            logger.debug(f"Error getting stats for {level}: {e}")
        
        stats["levels"][level] = level_stats
    
    # Totals
    stats["totals"] = {
        "queries": total_queries,
        "cache_hits": total_cache_hits,
        "cache_miss": total_cache_miss,
        "blocked": total_blocked,
        "cache_hit_rate": round((total_cache_hits / max(total_queries, 1)) * 100, 1),
    }
    
    # Summary
    stats["summary"] = {
        "active_levels": sum(1 for l in stats["levels"].values() if l["active"]),
    }
    
    return stats


@app.get("/api/v1/dns/stats/summary")
async def get_dns_stats_summary():
    """
    Minimal anonymous DNS stats summary.
    """
    try:
        full_stats = await get_dns_stats()
        return {
            "timestamp": full_stats["timestamp"],
            "gateway": full_stats["gateway"],
            "total_queries": full_stats["totals"]["queries"],
            "total_blocked": full_stats["totals"]["blocked"],
            "cache_hit_rate": full_stats["totals"]["cache_hit_rate"],
            "active_levels": full_stats["summary"]["active_levels"],
            "levels": {k: {
                "active": v["active"],
                "queries": v["queries"],
                "blocked": v["blocked"],
                "cache_hit_rate": v.get("cache_hit_rate", 0)
            } for k, v in full_stats["levels"].items()}
        }
    except Exception as e:
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "error": str(e)
        }


# ============================================================================
# DNS STATS LAPS - Like a chronometer
# ============================================================================

@app.post("/api/v1/dns/stats/lap")
async def create_dns_lap(name: str = None):
    """
    Create a new lap - snapshot current stats.
    Like pressing 'lap' on a chronometer.
    """
    global dns_laps
    
    # Get current cumulative stats
    current_stats = await get_dns_stats()
    
    lap_number = len(dns_laps) + 1
    lap = {
        "lap_number": lap_number,
        "name": name or f"Lap {lap_number}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "snapshot": {
            "totals": current_stats["totals"].copy(),
            "levels": {k: {
                "queries": v["queries"],
                "blocked": v["blocked"],
                "cache_hits": v["cache_hits"],
            } for k, v in current_stats["levels"].items()}
        }
    }
    
    dns_laps.append(lap)
    
    # Keep only last MAX_LAPS
    if len(dns_laps) > MAX_LAPS:
        dns_laps = dns_laps[-MAX_LAPS:]
    
    return {
        "message": f"Lap {lap_number} created",
        "lap": lap,
        "total_laps": len(dns_laps)
    }


@app.get("/api/v1/dns/stats/laps")
async def get_dns_laps():
    """
    Get all laps with deltas from previous lap.
    """
    current_stats = await get_dns_stats()
    
    laps_with_deltas = []
    
    for i, lap in enumerate(dns_laps):
        # Previous reference: either previous lap or zero
        if i == 0:
            prev_totals = {"queries": 0, "blocked": 0, "cache_hits": 0}
        else:
            prev_totals = dns_laps[i-1]["snapshot"]["totals"]
        
        # Calculate delta for this lap interval
        lap_delta = {
            "queries": lap["snapshot"]["totals"]["queries"] - prev_totals.get("queries", 0),
            "blocked": lap["snapshot"]["totals"]["blocked"] - prev_totals.get("blocked", 0),
            "cache_hits": lap["snapshot"]["totals"]["cache_hits"] - prev_totals.get("cache_hits", 0),
        }
        
        laps_with_deltas.append({
            **lap,
            "delta_from_previous": lap_delta
        })
    
    # Calculate "current" (since last lap)
    current_delta = None
    if dns_laps:
        last_lap = dns_laps[-1]
        current_delta = {
            "queries": current_stats["totals"]["queries"] - last_lap["snapshot"]["totals"]["queries"],
            "blocked": current_stats["totals"]["blocked"] - last_lap["snapshot"]["totals"]["blocked"],
            "cache_hits": current_stats["totals"]["cache_hits"] - last_lap["snapshot"]["totals"]["cache_hits"],
        }
    
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "gateway": os.getenv("GATEWAY_NAME", "unknown"),
        "cumulative": current_stats["totals"],
        "since_last_lap": current_delta,
        "laps": laps_with_deltas,
        "total_laps": len(dns_laps)
    }


@app.delete("/api/v1/dns/stats/laps")
async def clear_dns_laps():
    """
    Clear all laps (reset chronometer, but cumulative stats remain).
    """
    global dns_laps
    count = len(dns_laps)
    dns_laps = []
    return {
        "message": f"Cleared {count} laps",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.get("/api/v1/dns/stats/since/{lap_number}")
async def get_stats_since_lap(lap_number: int):
    """
    Get stats delta since a specific lap.
    """
    if lap_number < 1 or lap_number > len(dns_laps):
        return {"error": f"Invalid lap number. Valid: 1-{len(dns_laps)}"}
    
    lap = dns_laps[lap_number - 1]
    current_stats = await get_dns_stats()
    
    delta = {
        "queries": current_stats["totals"]["queries"] - lap["snapshot"]["totals"]["queries"],
        "blocked": current_stats["totals"]["blocked"] - lap["snapshot"]["totals"]["blocked"],
        "cache_hits": current_stats["totals"]["cache_hits"] - lap["snapshot"]["totals"]["cache_hits"],
    }
    
    # Per-level delta
    level_deltas = {}
    for level in ["d1", "d2", "d3"]:
        if level in current_stats["levels"] and level in lap["snapshot"]["levels"]:
            level_deltas[level] = {
                "queries": current_stats["levels"][level]["queries"] - lap["snapshot"]["levels"][level]["queries"],
                "blocked": current_stats["levels"][level]["blocked"] - lap["snapshot"]["levels"][level]["blocked"],
            }
    
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "gateway": os.getenv("GATEWAY_NAME", "unknown"),
        "since_lap": {
            "number": lap_number,
            "name": lap["name"],
            "timestamp": lap["timestamp"]
        },
        "delta": delta,
        "level_deltas": level_deltas,
        "cumulative": current_stats["totals"]
    }
