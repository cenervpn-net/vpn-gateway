# gateway_api/main.py
# RAM-ONLY MODE - No SQLite dependency
import os
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
            
            # Log decrypted config keys for debugging (no values!)
            logger.info(f"E2E decrypted keys: {list(decrypted_config.keys())}")
            logger.info(f"E2E tunnel_traffic: {decrypted_config.get('tunnel_traffic', 'NOT SET')}")
            logger.info(f"E2E obfuscation_level: {decrypted_config.get('obfuscation_level', 'NOT SET')}")
            
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
    standard_key = public_key.replace('_', '/').replace('-', '+')
    if standard_key.endswith('%3D'):
        standard_key = standard_key[:-3] + '='
    
    # Find config in memory store
    config = peer_store.get(standard_key)
    if not config:
        logger.error(f"Config not found for key: {standard_key}")
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
