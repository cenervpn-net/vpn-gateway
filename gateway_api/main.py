# gateway_api/main.py
from fastapi import FastAPI, Depends, HTTPException, Header, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional, List
from pydantic import BaseModel
import json
import logging
import psutil # Add this for Admin monitoring
from database import get_db, init_db
from models import WGConfig
from security import verify_admin_request
from wg_manager import WireGuardManager
from datetime import datetime
from utils import decrypt_payload, encrypt_response
from sqlalchemy import update
from contextlib import contextmanager


# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI()
wg = WireGuardManager()

# Connection pool for database operations
db_pool = {}

@contextmanager
def get_db_connection():
    """Get a database connection from the pool"""
    connection = db_pool.get()
    try:
        yield connection
    finally:
        db_pool.put(connection)

@app.on_event("startup")
async def startup_event():
    init_db()
    
    # Log startup
    logger.info("Gateway starting up - reconstructing peer configurations")
    try:
        wg.sync_and_reconstruct_peers()
        logger.info("Peer reconstruction completed successfully")
    except Exception as e:
        logger.error(f"Peer reconstruction failed: {e}")

class ConfigCreate(BaseModel):
    # Legacy required fields
    public_key: str
    request_id: str
    
    # New optional fields with legacy defaults
    protocol: Optional[str] = None  # None = IPv4 (legacy)
    tunnel_traffic: Optional[List[str]] = ['ipv4']  # Legacy default
    port: Optional[int] = 51820  # Legacy default
    dns: Optional[str] = 'd1'  # Legacy default
    
    # Add this field to capture the encrypted payload
    encrypted_payload: Optional[str] = None
    
    class Config:
        extra = "allow"  # Allow extra fields

class ConfigStatus(BaseModel):
    status: str  # active/suspended

async def suspend_peer(public_key: str, db: Session):
    """Background task to suspend a peer"""
    try:
        # Remove from WireGuard
        wg.remove_peer(public_key)
        
        # Update database status
        db.execute(
            update(WGConfig)
            .where(WGConfig.public_key == public_key)
            .values(status="suspended")
        )
        db.commit()
        
        logger.info(f"Suspended peer: {public_key}")
    except Exception as e:
        logger.error(f"Failed to suspend peer {public_key}: {e}")

@app.post("/api/v1/configurations/")
async def create_configuration(
    config: ConfigCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    body = json.dumps(config.dict(exclude_unset=True), sort_keys=True)
    verify_admin_request(signature, timestamp, body)
    
    # Add detailed logging
    logger.debug(f"Received configuration: {config.dict()}")
    logger.debug(f"Protocol: {config.protocol}")
    logger.debug(f"Tunnel traffic: {config.tunnel_traffic}")
    
    # Check for encrypted_payload
    if hasattr(config, 'encrypted_payload') and config.encrypted_payload:
        logger.debug(f"Encrypted payload present, length: {len(config.encrypted_payload)}")
        logger.debug(f"Encrypted payload (first 50 chars): {config.encrypted_payload[:50]}...")
        try:
            # Decrypt the payload
            decrypted_data = decrypt_payload(config.encrypted_payload)
            logger.debug(f"Decrypted payload: {decrypted_data}")
            
            # Update config with decrypted values
            if 'protocol' in decrypted_data:
                config.protocol = decrypted_data['protocol']
                logger.debug(f"Updated protocol to: {config.protocol}")
            if 'tunnel_traffic' in decrypted_data:
                config.tunnel_traffic = decrypted_data['tunnel_traffic']
                logger.debug(f"Updated tunnel_traffic to: {config.tunnel_traffic}")
            if 'dns' in decrypted_data:
                config.dns = decrypted_data['dns']
                logger.debug(f"Updated dns to: {config.dns}")
            if 'port' in decrypted_data:
                config.port = decrypted_data['port']
                logger.debug(f"Updated port to: {config.port}")
            
            logger.debug(f"Updated config with decrypted values: protocol={config.protocol}, tunnel_traffic={config.tunnel_traffic}")
        except Exception as e:
            logger.error(f"Failed to decrypt payload: {e}")
            logger.error(f"Encrypted payload (first 50 chars): {config.encrypted_payload[:50]}...")
    else:
        logger.debug("No encrypted payload found in request")
    
    # Check if peer exists
    existing_config = db.query(WGConfig).filter(WGConfig.public_key == config.public_key).first()
    if existing_config:
        return {"status": "exists"}
    
    # Add WireGuard peer (returns success, ipv4, ipv6)
    success, assigned_ipv4, assigned_ipv6 = wg.add_peer(
        config.public_key,
        protocol=config.protocol,
        tunnel_traffic=config.tunnel_traffic,
        port=config.port
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to configure WireGuard peer")

    # Add detailed logging before creating WGConfig
    logger.debug("Creating new WGConfig with values:")
    logger.debug(f"public_key: {config.public_key}")
    logger.debug(f"status: active")
    logger.debug(f"assigned_ip: {assigned_ipv4}")
    logger.debug(f"assigned_ipv6: {assigned_ipv6}")
    logger.debug(f"assigned_port: {config.port}")
    logger.debug(f"tunnel_traffic: {config.tunnel_traffic}")
    logger.debug(f"dns_choice: {config.dns}")
    logger.debug(f"allowed_ips: {wg.get_allowed_ips(config.tunnel_traffic)}")

    # Save both IPv4 and IPv6 addresses
    new_config = WGConfig(
        public_key=config.public_key,
        status="active",
        assigned_ip=assigned_ipv4,
        assigned_ipv6=assigned_ipv6,
        assigned_port=config.port,
        tunnel_traffic=config.tunnel_traffic,
        dns_choice=config.dns,
        allowed_ips=','.join(wg.get_allowed_ips(config.tunnel_traffic))  # Convert list to string
    )
    db.add(new_config)
    db.commit()
    
    # Return both addresses in the response
    response = {
        "status": "created",
        "assigned_ip": assigned_ipv4  # For backward compatibility
    }
    
    # Add IPv6 address if available
    if assigned_ipv6:
        response["assigned_ipv6"] = assigned_ipv6
    
    # Encrypt the response if the request had an encrypted payload
    if hasattr(config, 'encrypted_payload') and config.encrypted_payload:
        encrypted_response = encrypt_response(response)
        return {"encrypted_response": encrypted_response}
    else:
        return response

@app.put("/api/v1/configurations/{public_key}/status")
async def update_status(
    public_key: str,
    status: ConfigStatus,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    logger.debug(f"Updating status for key: {public_key}")
    # Only include fields that were explicitly set
    body = json.dumps(status.dict(exclude_unset=True), sort_keys=True)
    verify_admin_request(signature, timestamp, body)
    
        # Convert URL-safe key to standard format
    standard_key = public_key.replace('_', '/').replace('-', '+')
    if standard_key.endswith('%3D'):
        standard_key = standard_key[:-3] + '='
    logger.debug(f"Converted key: {public_key} -> {standard_key}")
    
    config = db.query(WGConfig).filter(WGConfig.public_key == standard_key).first()
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    if status.status == "suspended":
        # Add suspend to background tasks
        background_tasks.add_task(suspend_peer, standard_key, db)
        return {"status": "suspended"}
    elif status.status == "active":
        if not wg.verify_peer_exists(standard_key):
            success, _, _ = wg.add_peer(
                standard_key,
                protocol='dual' if config.assigned_ipv6 else None,
                tunnel_traffic=config.tunnel_traffic,
                port=config.assigned_port,
                assigned_ipv4=config.assigned_ip,
                assigned_ipv6=config.assigned_ipv6
            )
            if not success:
                raise HTTPException(status_code=500, detail="Failed to activate peer")
    
    config.status = status.status
    db.commit()
    
    return {"status": "updated"}

@app.delete("/api/v1/configurations/{public_key}")
async def delete_configuration(
    public_key: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    signature: str = Header(...),
    timestamp: str = Header(...)
):
    standard_key = public_key.replace('_', '/').replace('-', '+')
    if standard_key.endswith('%3D'):
        standard_key = standard_key[:-3] + '='
    
    config = db.query(WGConfig).filter(WGConfig.public_key == standard_key).first()
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")
    
    # Remove from WireGuard
    wg.remove_peer(standard_key)
    
    # Delete from database (not just suspend)
    db.delete(config)
    db.commit()
    
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
    db: Session = Depends(get_db),
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
    db: Session = Depends(get_db),
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
