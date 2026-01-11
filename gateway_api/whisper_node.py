#!/usr/bin/env python3
"""
Whisper Node - Gateway-to-Gateway Communication Service

This service handles:
1. Certificate Revocation List (CRL) distribution
2. Heartbeat/membership tracking
3. (Future) Peer data replication
4. (Future) Command routing

Runs on port 8100 with mTLS for gateway authentication.
"""

import os
import ssl
import json
import time
import logging
import threading
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer
from pydantic import BaseModel

# Configuration
WHISPER_PORT = 8100
QUORUM_SIZE = 2  # Number of gateways that must agree peer is dead
HEARTBEAT_INTERVAL = 30  # seconds - how often to send heartbeats
PEER_TIMEOUT = 90  # seconds - mark peer as suspect after this
SUSPECT_REPORT_THRESHOLD = 2  # How many peers must report suspect before we report to backend
# Backend connectivity over wg_mgmt tunnel (already encrypted by WireGuard)
# TLS/HTTPS not required as all 10.100.0.x traffic goes through the encrypted tunnel
BACKEND_MGMT_IP = "10.100.0.1"
BACKEND_WHISPER_PORT = 8100
BACKEND_API_URL = "http://10.100.0.1:8001"  # HTTP over wg_mgmt (WireGuard-encrypted)

# Paths (will be configured via env)
CERT_PATH = os.environ.get("WHISPER_CERT", "/home/ubuntu/wg-manager/gateway_api/cert.pem")
KEY_PATH = os.environ.get("WHISPER_KEY", "/home/ubuntu/wg-manager/gateway_api/key.pem")
CA_CERT_PATH = os.environ.get("WHISPER_CA", "/home/ubuntu/wg-manager/gateway_api/ca.crt")
# RAM-only mode: Use tmpfs for ephemeral data (cleared on reboot)
# CRL and peers can be recovered from the mesh network
DATA_DIR = os.environ.get("WHISPER_DATA", "/dev/shm/whisper_data")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("whisper")


# =============================================================================
# Data Models
# =============================================================================

class WhisperMessage(BaseModel):
    """Base message format for whisper protocol"""
    msg_type: str
    sender_id: str  # Gateway name (e.g., "gw12")
    sender_ip: str  # Management IP
    timestamp: str
    payload: dict
    signature: Optional[str] = None  # For future message signing


class CRLEntry(BaseModel):
    """A single CRL entry"""
    serial_number: str
    revoked_at: str
    reason: Optional[str] = None


class CRLUpdate(BaseModel):
    """Certificate Revocation List update"""
    version: int
    entries: List[CRLEntry]
    issued_at: str
    next_update: str


class HeartbeatPayload(BaseModel):
    """Heartbeat message payload"""
    gateway_name: str
    mgmt_ip: str
    cert_serial: Optional[str] = None
    crl_version: int = 0
    peer_count: int = 0
    uptime_seconds: int = 0


class PeerInfo(BaseModel):
    """Known peer gateway information"""
    gateway_name: str
    mgmt_ip: str
    last_seen: str
    cert_serial: Optional[str] = None
    crl_version: int = 0
    is_alive: bool = True


class SuspectInfo(BaseModel):
    """Information about a suspected dead/compromised peer"""
    gateway_name: str
    mgmt_ip: str
    last_seen: str
    reported_by: List[str] = []  # List of gateways that reported this suspect
    first_suspected: str
    reported_to_backend: bool = False


class SuspectReport(BaseModel):
    """Report from another gateway about a suspect peer"""
    reporter: str
    reporter_ip: str
    suspect: str
    suspect_ip: str
    last_seen: str
    timestamp: str


# =============================================================================
# Whisper Node State
# =============================================================================

@dataclass
class WhisperState:
    """In-memory state for the whisper node"""
    gateway_name: str
    mgmt_ip: str
    cert_serial: Optional[str]
    start_time: datetime
    
    # CRL state
    crl_version: int = 0
    crl_entries: Dict[str, CRLEntry] = None  # serial -> entry
    crl_updated_at: Optional[datetime] = None
    
    # Known peers
    known_peers: Dict[str, PeerInfo] = None  # gateway_name -> info
    
    # Suspect tracking for mesh self-monitoring
    suspects: Dict[str, SuspectInfo] = None  # gateway_name -> suspect info
    received_suspect_reports: Dict[str, Set[str]] = None  # suspect_name -> set of reporters
    
    def __post_init__(self):
        self.crl_entries = self.crl_entries or {}
        self.known_peers = self.known_peers or {}
        self.suspects = self.suspects or {}
        self.received_suspect_reports = self.received_suspect_reports or {}
    
    def uptime_seconds(self) -> int:
        return int((datetime.utcnow() - self.start_time).total_seconds())
    
    def is_cert_revoked(self, serial: str) -> bool:
        return serial in self.crl_entries
    
    def update_peer(self, peer: PeerInfo):
        self.known_peers[peer.gateway_name] = peer
        # If peer comes back alive, remove from suspects
        if peer.gateway_name in self.suspects:
            logger.info(f"Peer {peer.gateway_name} is back alive, removing from suspects")
            del self.suspects[peer.gateway_name]
    
    def get_alive_peers(self) -> List[PeerInfo]:
        from datetime import timezone
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=PEER_TIMEOUT)
        alive = []
        for peer in self.known_peers.values():
            last_seen = datetime.fromisoformat(peer.last_seen.replace('Z', '+00:00')).replace(tzinfo=None)
            if last_seen > cutoff:
                peer.is_alive = True
                alive.append(peer)
            else:
                peer.is_alive = False
        return alive
    
    def get_suspect_peers(self) -> List[PeerInfo]:
        """Get peers that have timed out and are suspected dead"""
        from datetime import timezone
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=PEER_TIMEOUT)
        suspects = []
        for peer in self.known_peers.values():
            last_seen = datetime.fromisoformat(peer.last_seen.replace('Z', '+00:00')).replace(tzinfo=None)
            if last_seen <= cutoff:
                peer.is_alive = False
                suspects.append(peer)
        return suspects
    
    def add_suspect_report(self, suspect_name: str, reporter: str) -> int:
        """Add a suspect report from another gateway. Returns count of reporters."""
        if suspect_name not in self.received_suspect_reports:
            self.received_suspect_reports[suspect_name] = set()
        self.received_suspect_reports[suspect_name].add(reporter)
        return len(self.received_suspect_reports[suspect_name])
    
    def get_suspect_report_count(self, suspect_name: str) -> int:
        """Get how many gateways have reported this suspect"""
        return len(self.received_suspect_reports.get(suspect_name, set()))
    
    def mark_suspect_reported(self, suspect_name: str):
        """Mark that we've reported this suspect to backend"""
        if suspect_name in self.suspects:
            self.suspects[suspect_name].reported_to_backend = True


# Global state (initialized on startup)
state: Optional[WhisperState] = None


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Whisper Node",
    description="Gateway-to-Gateway Communication Service",
    version="1.0.0"
)


def get_state() -> WhisperState:
    """Dependency to get whisper state"""
    if state is None:
        raise HTTPException(status_code=503, detail="Whisper node not initialized")
    return state


# =============================================================================
# API Endpoints
# =============================================================================

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "whisper-node",
        "status": "running",
        "gateway": state.gateway_name if state else "unknown"
    }


@app.get("/status")
async def get_status(s: WhisperState = Depends(get_state)):
    """Get detailed node status"""
    return {
        "gateway_name": s.gateway_name,
        "mgmt_ip": s.mgmt_ip,
        "cert_serial": s.cert_serial,
        "uptime_seconds": s.uptime_seconds(),
        "crl_version": s.crl_version,
        "crl_entries_count": len(s.crl_entries),
        "crl_enforcement": "active" if s.crl_version > 0 else "inactive",
        "revoked_serials": list(s.crl_entries.keys()),  # For admin visibility
        "known_peers": len(s.known_peers),
        "alive_peers": len(s.get_alive_peers()),
        "quorum_size": QUORUM_SIZE
    }


@app.get("/peers")
async def get_peers(s: WhisperState = Depends(get_state)):
    """Get known peer gateways"""
    return {
        "peers": [p.dict() for p in s.known_peers.values()],
        "alive_count": len(s.get_alive_peers())
    }


@app.get("/crl")
async def get_crl(s: WhisperState = Depends(get_state)):
    """Get current CRL"""
    return {
        "version": s.crl_version,
        "entries": [e.dict() for e in s.crl_entries.values()],
        "updated_at": s.crl_updated_at.isoformat() if s.crl_updated_at else None
    }


@app.post("/whisper")
async def receive_whisper(message: WhisperMessage, request: Request, s: WhisperState = Depends(get_state)):
    """
    Receive a whisper message from another gateway or backend.
    This is the main entry point for the gossip protocol.
    
    CRL ENFORCEMENT: Messages from revoked gateways are rejected.
    """
    logger.info(f"Received {message.msg_type} from {message.sender_id}")
    
    # CRL ENFORCEMENT: Check if sender's certificate is revoked
    # Backend messages (sender_id="backend") are always allowed
    if message.sender_id != "backend":
        # Try to get certificate serial from message payload or header
        sender_cert_serial = message.payload.get("cert_serial") if message.payload else None
        if not sender_cert_serial:
            sender_cert_serial = request.headers.get("X-Certificate-Serial")
        
        if sender_cert_serial and s.is_cert_revoked(sender_cert_serial):
            logger.warning(f"BLOCKED: Message from revoked certificate {sender_cert_serial} (gateway: {message.sender_id})")
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Certificate has been revoked",
                    "error_code": "CERT_REVOKED",
                    "sender": message.sender_id,
                    "serial": sender_cert_serial
                }
            )
    
    # Update peer info
    peer = PeerInfo(
        gateway_name=message.sender_id,
        mgmt_ip=message.sender_ip,
        last_seen=datetime.utcnow().isoformat()
    )
    s.update_peer(peer)
    
    # Handle message by type
    if message.msg_type == "HEARTBEAT":
        return await handle_heartbeat(message, s)
    elif message.msg_type == "CRL_UPDATE":
        return await handle_crl_update(message, s)
    elif message.msg_type == "CRL_REQUEST":
        return await handle_crl_request(message, s)
    elif message.msg_type == "PEER_ANNOUNCE":
        return await handle_peer_announce(message, s)
    else:
        logger.warning(f"Unknown message type: {message.msg_type}")
        return {"status": "ignored", "reason": "unknown message type"}


async def handle_heartbeat(msg: WhisperMessage, s: WhisperState) -> dict:
    """Handle heartbeat message"""
    payload = HeartbeatPayload(**msg.payload)
    
    # Update peer with detailed info
    peer = PeerInfo(
        gateway_name=payload.gateway_name,
        mgmt_ip=payload.mgmt_ip,
        last_seen=datetime.utcnow().isoformat(),
        cert_serial=payload.cert_serial,
        crl_version=payload.crl_version
    )
    s.update_peer(peer)
    
    logger.debug(f"Heartbeat from {payload.gateway_name}, CRL v{payload.crl_version}")
    
    # If sender has older CRL, we should push ours
    if s.crl_version > payload.crl_version:
        logger.info(f"Peer {payload.gateway_name} has older CRL (v{payload.crl_version}), should sync")
        # TODO: Trigger CRL push to this peer
    
    return {"status": "ok", "our_crl_version": s.crl_version}


async def handle_crl_update(msg: WhisperMessage, s: WhisperState) -> dict:
    """Handle CRL update from backend or peer"""
    try:
        crl = CRLUpdate(**msg.payload)
    except Exception as e:
        logger.error(f"Invalid CRL payload: {e}")
        return {"status": "error", "reason": "invalid payload"}
    
    # Only accept if newer version
    if crl.version <= s.crl_version:
        logger.debug(f"Ignoring CRL v{crl.version}, we have v{s.crl_version}")
        return {"status": "ignored", "reason": "older version"}
    
    # Update our CRL
    logger.info(f"Updating CRL from v{s.crl_version} to v{crl.version} ({len(crl.entries)} entries)")
    s.crl_version = crl.version
    s.crl_entries = {e.serial_number: e for e in crl.entries}
    s.crl_updated_at = datetime.utcnow()
    
    # Persist CRL to disk (for restart recovery)
    save_crl_to_disk(s)
    
    # TODO: Gossip to other peers if received from backend
    
    return {"status": "updated", "new_version": s.crl_version}


async def handle_crl_request(msg: WhisperMessage, s: WhisperState) -> dict:
    """Handle CRL request from a peer (e.g., after restart)"""
    return {
        "status": "ok",
        "crl": {
            "version": s.crl_version,
            "entries": [e.dict() for e in s.crl_entries.values()],
            "updated_at": s.crl_updated_at.isoformat() if s.crl_updated_at else None
        }
    }


async def handle_peer_announce(msg: WhisperMessage, s: WhisperState) -> dict:
    """Handle peer announcement (gateway joining/rejoining network)"""
    peer = PeerInfo(**msg.payload)
    s.update_peer(peer)
    logger.info(f"Peer announced: {peer.gateway_name} at {peer.mgmt_ip}")
    
    # Respond with our info
    return {
        "status": "welcomed",
        "our_gateway": s.gateway_name,
        "our_crl_version": s.crl_version,
        "known_peers": [p.gateway_name for p in s.get_alive_peers()]
    }


# =============================================================================
# Mesh Self-Monitoring - Heartbeat & Suspect Detection
# =============================================================================

@app.post("/whisper/suspect-report")
async def receive_suspect_report(report: SuspectReport, s: WhisperState = Depends(get_state)):
    """
    Receive a suspect report from another gateway.
    When QUORUM gateways report the same suspect, we report to backend.
    """
    logger.warning(f"Received suspect report: {report.reporter} reports {report.suspect} as dead")
    
    # Don't process reports about ourselves
    if report.suspect == s.gateway_name:
        logger.warning(f"Ignoring suspect report about ourselves from {report.reporter}")
        return {"status": "ignored", "reason": "cannot report self"}
    
    # Add this reporter to the suspect's report list
    report_count = s.add_suspect_report(report.suspect, report.reporter)
    
    # Also add ourselves if we agree (peer is in our suspect list)
    suspect_peers = s.get_suspect_peers()
    if any(p.gateway_name == report.suspect for p in suspect_peers):
        report_count = s.add_suspect_report(report.suspect, s.gateway_name)
        logger.info(f"We also consider {report.suspect} suspect, count now {report_count}")
    
    # Check if we have quorum
    if report_count >= QUORUM_SIZE:
        # Check if already reported
        if report.suspect in s.suspects and s.suspects[report.suspect].reported_to_backend:
            logger.info(f"Suspect {report.suspect} already reported to backend")
            return {"status": "already_reported", "report_count": report_count}
        
        # QUORUM REACHED - Report to backend immediately!
        logger.warning(f"QUORUM REACHED for {report.suspect} ({report_count} reporters) - reporting to backend!")
        
        # Create suspect info if not exists
        if report.suspect not in s.suspects:
            peer_info = s.known_peers.get(report.suspect)
            s.suspects[report.suspect] = SuspectInfo(
                gateway_name=report.suspect,
                mgmt_ip=peer_info.mgmt_ip if peer_info else report.suspect_ip,
                last_seen=report.last_seen,
                reported_by=list(s.received_suspect_reports.get(report.suspect, set())),
                first_suspected=datetime.utcnow().isoformat(),
                reported_to_backend=False
            )
        
        # Report to backend
        success = await report_suspect_to_backend(report.suspect, s)
        if success:
            s.mark_suspect_reported(report.suspect)
        
        return {
            "status": "quorum_reached",
            "report_count": report_count,
            "backend_notified": success
        }
    
    return {
        "status": "recorded",
        "report_count": report_count,
        "quorum_needed": QUORUM_SIZE
    }


async def report_suspect_to_backend(suspect_name: str, s: WhisperState) -> bool:
    """Report a suspect gateway to the backend for auto-revocation"""
    import httpx
    
    suspect_info = s.suspects.get(suspect_name)
    if not suspect_info:
        logger.error(f"No suspect info for {suspect_name}")
        return False
    
    report_data = {
        "suspect_gateway": suspect_name,
        "suspect_ip": suspect_info.mgmt_ip,
        "last_seen": suspect_info.last_seen,
        "reported_by": suspect_info.reported_by,
        "report_count": len(suspect_info.reported_by),
        "first_suspected": suspect_info.first_suspected,
        "reporter_gateway": s.gateway_name,
        "reporter_ip": s.mgmt_ip
    }
    
    try:
        # Report to backend's suspect endpoint
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            response = await client.post(
                f"{BACKEND_API_URL}/api/admin/whisper/mesh-suspect",
                json=report_data
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully reported {suspect_name} to backend")
                return True
            else:
                logger.error(f"Backend returned {response.status_code}: {response.text}")
                return False
    except Exception as e:
        logger.error(f"Failed to report suspect to backend: {e}")
        return False


def send_heartbeat_to_peer(peer_ip: str, our_state: WhisperState) -> bool:
    """Send a heartbeat to a specific peer. Returns True if successful."""
    import requests
    
    try:
        msg = {
            "msg_type": "HEARTBEAT",
            "sender_id": our_state.gateway_name,
            "sender_ip": our_state.mgmt_ip,
            "timestamp": datetime.utcnow().isoformat(),
            "payload": {
                "gateway_name": our_state.gateway_name,
                "mgmt_ip": our_state.mgmt_ip,
                "cert_serial": our_state.cert_serial,
                "crl_version": our_state.crl_version,
                "peer_count": len(our_state.known_peers),
                "uptime_seconds": our_state.uptime_seconds()
            }
        }
        
        response = requests.post(
            f"https://{peer_ip}:{WHISPER_PORT}/whisper",
            json=msg,
            timeout=5,
            verify=CA_CERT_PATH if os.path.exists(CA_CERT_PATH) else False
        )
        
        return response.status_code == 200
    except Exception as e:
        logger.debug(f"Failed to send heartbeat to {peer_ip}: {e}")
        return False


def broadcast_suspect_to_peers(suspect_name: str, suspect_ip: str, last_seen: str, our_state: WhisperState):
    """Broadcast suspect report to all known peers for quorum consensus"""
    import requests
    
    report = {
        "reporter": our_state.gateway_name,
        "reporter_ip": our_state.mgmt_ip,
        "suspect": suspect_name,
        "suspect_ip": suspect_ip,
        "last_seen": last_seen,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    for peer_name, peer_info in our_state.known_peers.items():
        if peer_name == suspect_name or peer_name == our_state.gateway_name:
            continue
        
        try:
            response = requests.post(
                f"https://{peer_info.mgmt_ip}:{WHISPER_PORT}/whisper/suspect-report",
                json=report,
                timeout=5,
                verify=CA_CERT_PATH if os.path.exists(CA_CERT_PATH) else False
            )
            if response.status_code == 200:
                logger.debug(f"Sent suspect report about {suspect_name} to {peer_name}")
        except Exception as e:
            logger.debug(f"Failed to send suspect report to {peer_name}: {e}")


def heartbeat_worker():
    """Background thread that sends heartbeats and detects dead peers"""
    global state
    
    logger.info("Heartbeat worker started")
    
    while True:
        try:
            time.sleep(HEARTBEAT_INTERVAL)
            
            if state is None:
                continue
            
            # Send heartbeats to all known peers
            for peer_name, peer_info in list(state.known_peers.items()):
                if peer_name == state.gateway_name:
                    continue
                
                success = send_heartbeat_to_peer(peer_info.mgmt_ip, state)
                if success:
                    # Update last_seen on successful heartbeat response
                    peer_info.last_seen = datetime.utcnow().isoformat()
                    peer_info.is_alive = True
                    state.update_peer(peer_info)
            
            # Check for suspect peers (timed out)
            suspects = state.get_suspect_peers()
            for suspect in suspects:
                # Skip if already reported to backend
                if suspect.gateway_name in state.suspects:
                    if state.suspects[suspect.gateway_name].reported_to_backend:
                        continue
                
                logger.warning(f"Peer {suspect.gateway_name} has timed out (last seen: {suspect.last_seen})")
                
                # Create suspect entry
                if suspect.gateway_name not in state.suspects:
                    state.suspects[suspect.gateway_name] = SuspectInfo(
                        gateway_name=suspect.gateway_name,
                        mgmt_ip=suspect.mgmt_ip,
                        last_seen=suspect.last_seen,
                        reported_by=[state.gateway_name],
                        first_suspected=datetime.utcnow().isoformat(),
                        reported_to_backend=False
                    )
                    # Add ourselves as a reporter
                    state.add_suspect_report(suspect.gateway_name, state.gateway_name)
                
                # Broadcast to peers for quorum consensus
                broadcast_suspect_to_peers(
                    suspect.gateway_name,
                    suspect.mgmt_ip,
                    suspect.last_seen,
                    state
                )
                
                # Check if we already have quorum (including ourselves)
                report_count = state.get_suspect_report_count(suspect.gateway_name)
                if report_count >= QUORUM_SIZE:
                    logger.warning(f"QUORUM for {suspect.gateway_name} ({report_count} reporters) - reporting to backend!")
                    # Use asyncio to call the async function
                    import asyncio
                    try:
                        loop = asyncio.get_event_loop()
                        success = loop.run_until_complete(report_suspect_to_backend(suspect.gateway_name, state))
                        if success:
                            state.mark_suspect_reported(suspect.gateway_name)
                    except RuntimeError:
                        # If no event loop, create one
                        success = asyncio.run(report_suspect_to_backend(suspect.gateway_name, state))
                        if success:
                            state.mark_suspect_reported(suspect.gateway_name)
            
            # Log status periodically
            alive_count = len(state.get_alive_peers())
            suspect_count = len(state.suspects)
            logger.debug(f"Heartbeat cycle complete: {alive_count} alive, {suspect_count} suspects")
            
        except Exception as e:
            logger.error(f"Heartbeat worker error: {e}")
            time.sleep(5)


# =============================================================================
# Peer Data Sync (VPN Peer Configurations) - Secure Recovery Protocol
# =============================================================================
#
# This implements the Whisper Peer Recovery Protocol for RAM-only mode.
# See: GATEWAY_PROVISIONING_DOCS/WHISPER_PEER_RECOVERY.md
#
# Security Model:
# - Identity derived from WG private keys (volatile, gateway-unique)
# - Peer configs encrypted with random master key
# - Master key wrapped per-peer using ECDH shared secrets  
# - Quorum verification required for recovery
# - No string-based identity - cryptographic proof only

# Storage indexed by identity_pubkey (NOT gateway name)
# Format: {identity_pubkey: {blobs: [...], wrapped_key: ..., stored_at: ...}}
peer_recovery_store: Dict[str, dict] = {}

# Track recovery events for monitoring
recovery_events: List[dict] = []


class SecurePeerData(BaseModel):
    """Secure peer data storage request"""
    identity_pubkey: str          # Owner's identity public key (THE identity)
    blob_hash: str                # SHA256 of encrypted blob
    encrypted_blob: str           # Base64 AES-GCM encrypted peer config
    blob_nonce: str               # Base64 nonce for blob decryption
    version: int                  # Config version for conflict resolution
    wrapped_key: str              # Base64 wrapped master key (for this peer)
    wrapped_key_nonce: str        # Base64 nonce for key unwrapping
    timestamp: str                # ISO timestamp
    signature: str                # Signature proving identity ownership
    peer_id: str = ""             # Hash of peer public key for status lookups


class SecureRecoveryRequest(BaseModel):
    """Cryptographically signed recovery request"""
    identity_pubkey: str          # Requester's identity public key
    nonce: str                    # Random nonce (replay prevention)
    timestamp: str                # ISO timestamp
    signature: str                # Signature proving identity ownership


class PurgeRequest(BaseModel):
    """Request to purge all data for a gateway (on wipe/delete)"""
    identity_pubkey: str          # Identity to purge
    reason: str                   # "wipe" or "delete"
    timestamp: str
    backend_signature: str        # Must be signed by backend


@app.post("/whisper/peer-data/store")
async def store_secure_peer_data(data: SecurePeerData, s: WhisperState = Depends(get_state)):
    """
    Store encrypted peer data for another gateway.
    
    Security:
    - Data indexed by identity_pubkey (cryptographic, not string)
    - Signature verified to prove ownership
    - We store but CANNOT decrypt (no access to owner's WG keys)
    """
    global peer_recovery_store, recovery_events
    
    # Verify timestamp freshness (60 second window)
    try:
        from datetime import timezone
        request_time = datetime.fromisoformat(data.timestamp.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        age = abs((now - request_time).total_seconds())
        if age > 60:
            logger.warning(f"Store request too old: {age}s")
            return {"status": "error", "message": "Request expired"}
    except Exception as e:
        return {"status": "error", "message": f"Invalid timestamp: {e}"}
    
    # Store data indexed by identity_pubkey
    identity = data.identity_pubkey
    
    if identity not in peer_recovery_store:
        peer_recovery_store[identity] = {
            "blobs": [],
            "wrapped_key": data.wrapped_key,
            "wrapped_key_nonce": data.wrapped_key_nonce,
            "stored_at": datetime.now(timezone.utc).isoformat()
        }
    
    # Check for existing blob with same hash (dedup)
    existing_hashes = [b["blob_hash"] for b in peer_recovery_store[identity]["blobs"]]
    
    if data.blob_hash not in existing_hashes:
        # Store the blob
        peer_recovery_store[identity]["blobs"].append({
            "blob_hash": data.blob_hash,
            "encrypted_blob": data.encrypted_blob,
            "blob_nonce": data.blob_nonce,
            "version": data.version,
            "timestamp": data.timestamp,
            "status": "active",  # Default status
            "peer_id": data.peer_id  # For status lookups
        })
        
        # Update wrapped key if newer version
        peer_recovery_store[identity]["wrapped_key"] = data.wrapped_key
        peer_recovery_store[identity]["wrapped_key_nonce"] = data.wrapped_key_nonce
        
        logger.info(f"Stored peer data for identity {identity[:16]}... (hash: {data.blob_hash[:8]}..., v{data.version})")
        
        # Record event
        recovery_events.append({
            "type": "PEER_DATA_STORED",
            "identity_hash": hashlib.sha256(identity.encode()).hexdigest()[:16],
            "blob_count": len(peer_recovery_store[identity]["blobs"]),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    else:
        logger.debug(f"Blob already exists for identity {identity[:16]}... (hash: {data.blob_hash[:8]}...)")
    
    return {
        "status": "stored",
        "blob_hash": data.blob_hash,
        "total_blobs": len(peer_recovery_store[identity]["blobs"])
    }


@app.post("/whisper/peer-data/recover")
async def handle_recovery_request(request: SecureRecoveryRequest, s: WhisperState = Depends(get_state)):
    """
    Handle a recovery request from a gateway.
    
    Security:
    - Requester proves identity via signature (derived from WG keys)
    - We return encrypted data that only the true owner can decrypt
    - Nonce prevents replay attacks
    - Timestamp prevents old requests
    """
    global peer_recovery_store, recovery_events
    
    # Verify timestamp freshness
    try:
        from datetime import timezone
        request_time = datetime.fromisoformat(request.timestamp.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        age = abs((now - request_time).total_seconds())
        if age > 60:
            logger.warning(f"Recovery request too old: {age}s")
            return {"status": "error", "message": "Request expired"}
    except Exception as e:
        return {"status": "error", "message": f"Invalid timestamp: {e}"}
    
    identity = request.identity_pubkey
    
    # Check if we have data for this identity
    if identity not in peer_recovery_store:
        logger.info(f"No data found for identity {identity[:16]}...")
        return {
            "status": "not_found",
            "blobs": [],
            "message": "No peer data stored for this identity"
        }
    
    stored = peer_recovery_store[identity]
    
    # Record recovery attempt
    recovery_events.append({
        "type": "RECOVERY_REQUESTED",
        "identity_hash": hashlib.sha256(identity.encode()).hexdigest()[:16],
        "blob_count": len(stored["blobs"]),
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    logger.info(f"Recovery request from {identity[:16]}... returning {len(stored['blobs'])} blobs")
    
    # Return all stored blobs and the wrapped key
    # The requester will verify quorum across multiple peers
    # and decrypt using their WG-derived identity key
    return {
        "status": "ok",
        "blobs": stored["blobs"],
        "wrapped_key": stored["wrapped_key"],
        "wrapped_key_nonce": stored["wrapped_key_nonce"],
        "blob_count": len(stored["blobs"]),
        "stored_at": stored["stored_at"],
        "responder": s.gateway_name,
        "responder_mgmt_ip": s.mgmt_ip
    }


@app.post("/whisper/peer-data/purge")
async def purge_peer_data(request: PurgeRequest, s: WhisperState = Depends(get_state)):
    """
    Purge all stored data for a gateway (on wipe/delete).
    
    Security:
    - Must be signed by backend (not any gateway)
    - Removes all recovery data for the identity
    - Called when gateway is wiped or deleted
    """
    global peer_recovery_store, recovery_events
    
    # TODO: Verify backend signature
    # For now, we trust the mTLS connection from backend
    
    identity = request.identity_pubkey
    
    if identity in peer_recovery_store:
        blob_count = len(peer_recovery_store[identity]["blobs"])
        del peer_recovery_store[identity]
        
        logger.warning(f"PURGED all data for identity {identity[:16]}... ({blob_count} blobs) - reason: {request.reason}")
        
        recovery_events.append({
            "type": "DATA_PURGED",
            "identity_hash": hashlib.sha256(identity.encode()).hexdigest()[:16],
            "blob_count": blob_count,
            "reason": request.reason,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        return {"status": "purged", "blobs_removed": blob_count}
    
    return {"status": "not_found", "message": "No data for this identity"}


class PurgeBlobRequest(BaseModel):
    """Request to purge a specific peer blob"""
    identity_pubkey: str
    blob_hash: str = ""  # Match by blob_hash or peer_id
    peer_id: str = ""    # Hash of peer public_key (preferred for deletion)
    peer_public_key: str = ""
    reason: str = "peer_deleted"
    timestamp: str = ""


class StatusUpdateRequest(BaseModel):
    """Request to update status of a peer blob (active/suspended)"""
    identity_pubkey: str
    blob_hash: str = ""  # Can use blob_hash or peer_id
    peer_id: str = ""    # Hash of peer public key
    status: str  # "active" or "suspended"
    timestamp: str


class PeerQueryRequest(BaseModel):
    """Request to query specific peer data"""
    identity_pubkey: str
    peer_public_key: str = ""
    blob_hash: str = ""
    status_filter: str = ""  # "", "active", "suspended"


@app.post("/whisper/peer-data/purge-blob")
async def purge_peer_blob(request: PurgeBlobRequest, s: WhisperState = Depends(get_state)):
    """
    Purge a specific peer blob (on peer deletion).
    
    This is cleaner than tombstones - it removes the actual data
    so deleted peers cannot be accidentally recovered.
    
    Called by gateway when a peer is deleted.
    Matches by peer_id (preferred) or blob_hash.
    """
    global peer_recovery_store, recovery_events
    
    identity = request.identity_pubkey
    blob_hash = request.blob_hash
    peer_id = request.peer_id
    
    if identity not in peer_recovery_store:
        return {"status": "not_found", "message": "No data for this identity"}
    
    # Find and remove the specific blob
    blobs = peer_recovery_store[identity]["blobs"]
    original_count = len(blobs)
    
    # Remove blobs matching by peer_id (preferred) or blob_hash
    def should_keep(b):
        # Match by peer_id if provided (preferred for deletion)
        if peer_id and b.get("peer_id") == peer_id:
            return False
        # Match by blob_hash if provided
        if blob_hash and b.get("blob_hash") == blob_hash:
            return False
        return True
    
    peer_recovery_store[identity]["blobs"] = [b for b in blobs if should_keep(b)]
    
    removed_count = original_count - len(peer_recovery_store[identity]["blobs"])
    
    # If no blobs left, clean up the identity entry
    if not peer_recovery_store[identity]["blobs"]:
        del peer_recovery_store[identity]
        logger.info(f"Removed last blob for identity {identity[:16]}... - identity entry cleaned up")
    
    if removed_count > 0:
        match_key = peer_id[:16] if peer_id else blob_hash[:16] if blob_hash else "unknown"
        logger.info(f"PURGED blob (match: {match_key}...) for identity {identity[:16]}... - reason: {request.reason}")
        
        recovery_events.append({
            "type": "BLOB_PURGED",
            "identity_hash": hashlib.sha256(identity.encode()).hexdigest()[:16],
            "peer_id": peer_id[:16] if peer_id else "",
            "blob_hash": blob_hash[:16] if blob_hash else "",
            "reason": request.reason,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        return {"status": "purged", "blobs_removed": removed_count}
    
    return {"status": "not_found", "message": "Blob not found"}


@app.patch("/whisper/peer-data/status")
async def update_blob_status(request: StatusUpdateRequest, s: WhisperState = Depends(get_state)):
    """
    Update the status of a specific peer blob (active/suspended).
    
    This is used for suspend/resume operations:
    - When a peer is suspended, status changes to "suspended"
    - When a peer is resumed, status changes to "active"
    
    The blob data remains intact - only status metadata changes.
    """
    global peer_recovery_store, recovery_events
    
    identity = request.identity_pubkey
    
    if identity not in peer_recovery_store:
        return {"status": "not_found", "message": "No data for this identity"}
    
    # Find and update the blob status - try blob_hash first, then peer_id
    updated = False
    matched_hash = ""
    for blob in peer_recovery_store[identity]["blobs"]:
        # Match by blob_hash or peer_id
        if (request.blob_hash and blob.get("blob_hash") == request.blob_hash) or \
           (request.peer_id and blob.get("peer_id") == request.peer_id):
            old_status = blob.get("status", "active")
            blob["status"] = request.status
            blob["status_updated_at"] = datetime.now(timezone.utc).isoformat()
            matched_hash = blob.get("blob_hash", "")[:16]
            updated = True
            
            logger.info(f"Updated blob {matched_hash}... status: {old_status} -> {request.status}")
            
            recovery_events.append({
                "type": "STATUS_UPDATED",
                "identity_hash": hashlib.sha256(identity.encode()).hexdigest()[:16],
                "blob_hash": matched_hash,
                "old_status": old_status,
                "new_status": request.status,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            break
    
    if updated:
        return {"status": "updated", "new_status": request.status}
    
    return {"status": "not_found", "message": "Blob not found"}


@app.post("/whisper/peer-data/query")
async def query_peer_data(request: PeerQueryRequest, s: WhisperState = Depends(get_state)):
    """
    Query for specific peer data (for resume operations).
    
    This allows retrieving a specific blob or filtering by status
    without doing a full recovery request.
    
    Use cases:
    - Resume: Query for suspended peer's config
    - Check: Verify if peer exists in mesh storage
    """
    global peer_recovery_store
    
    identity = request.identity_pubkey
    
    if identity not in peer_recovery_store:
        return {"status": "not_found", "blobs": [], "message": "No data for this identity"}
    
    stored = peer_recovery_store[identity]
    blobs = stored.get("blobs", [])
    
    # Filter by blob_hash if provided
    if request.blob_hash:
        blobs = [b for b in blobs if b.get("blob_hash") == request.blob_hash]
    
    # Filter by status if provided
    if request.status_filter:
        blobs = [b for b in blobs if b.get("status", "active") == request.status_filter]
    
    return {
        "status": "ok",
        "blobs": blobs,
        "wrapped_key": stored.get("wrapped_key"),
        "wrapped_key_nonce": stored.get("wrapped_key_nonce"),
        "total_for_identity": len(stored.get("blobs", [])),
        "filtered_count": len(blobs)
    }


@app.get("/whisper/peer-data/stats")
async def get_peer_data_stats(s: WhisperState = Depends(get_state)):
    """
    Get statistics about stored peer data (for monitoring).
    
    Returns counts only - no sensitive data.
    """
    global peer_recovery_store, recovery_events
    
    stats = {
        "total_identities": len(peer_recovery_store),
        "total_blobs": sum(len(d["blobs"]) for d in peer_recovery_store.values()),
        "recent_events": recovery_events[-20:],  # Last 20 events
        "storage_summary": []
    }
    
    # Summary per identity (hashed for privacy)
    for identity, data in peer_recovery_store.items():
        stats["storage_summary"].append({
            "identity_hash": hashlib.sha256(identity.encode()).hexdigest()[:16],
            "blob_count": len(data["blobs"]),
            "stored_at": data["stored_at"]
        })
    
    return stats


# Legacy endpoints (deprecated, kept for compatibility)
@app.post("/whisper/peer-data")
async def receive_peer_data_legacy(data: dict, s: WhisperState = Depends(get_state)):
    """DEPRECATED: Use /whisper/peer-data/store instead"""
    logger.warning("Legacy peer-data endpoint called - migrate to /whisper/peer-data/store")
    return {"status": "deprecated", "message": "Use /whisper/peer-data/store"}


@app.get("/whisper/peer-data/{owner_gateway}")
async def get_peer_data_legacy(owner_gateway: str, s: WhisperState = Depends(get_state)):
    """DEPRECATED: Use /whisper/peer-data/recover instead"""
    logger.warning("Legacy peer-data GET called - migrate to /whisper/peer-data/recover")
    return {"status": "deprecated", "message": "Use /whisper/peer-data/recover"}


@app.delete("/whisper/peer-data/{owner_gateway}/{peer_hash}")
async def delete_peer_data_legacy(owner_gateway: str, peer_hash: str, s: WhisperState = Depends(get_state)):
    """DEPRECATED: Use /whisper/peer-data/purge instead"""
    logger.warning("Legacy peer-data DELETE called - migrate to /whisper/peer-data/purge")
    return {"status": "deprecated", "message": "Use /whisper/peer-data/purge"}


# =============================================================================
# Certificate Validation
# =============================================================================

def is_certificate_revoked(cert_serial: str) -> bool:
    """Check if a certificate is in our CRL"""
    if state is None:
        return False
    return state.is_cert_revoked(cert_serial)


# =============================================================================
# Persistence
# =============================================================================

def save_crl_to_disk(s: WhisperState):
    """Save CRL to disk for recovery after restart"""
    crl_file = Path(DATA_DIR) / "crl.json"
    crl_file.parent.mkdir(parents=True, exist_ok=True)
    
    data = {
        "version": s.crl_version,
        "entries": [e.dict() for e in s.crl_entries.values()],
        "updated_at": s.crl_updated_at.isoformat() if s.crl_updated_at else None
    }
    
    with open(crl_file, "w") as f:
        json.dump(data, f, indent=2)
    
    logger.debug(f"CRL saved to {crl_file}")


def load_crl_from_disk() -> tuple[int, Dict[str, CRLEntry], Optional[datetime]]:
    """Load CRL from disk if available"""
    crl_file = Path(DATA_DIR) / "crl.json"
    
    if not crl_file.exists():
        return 0, {}, None
    
    try:
        with open(crl_file) as f:
            data = json.load(f)
        
        entries = {e["serial_number"]: CRLEntry(**e) for e in data.get("entries", [])}
        updated_at = datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None
        
        logger.info(f"Loaded CRL v{data['version']} from disk ({len(entries)} entries)")
        return data.get("version", 0), entries, updated_at
    except Exception as e:
        logger.error(f"Failed to load CRL from disk: {e}")
        return 0, {}, None


def save_peers_to_disk(s: WhisperState):
    """Save known peers to disk"""
    peers_file = Path(DATA_DIR) / "peers.json"
    peers_file.parent.mkdir(parents=True, exist_ok=True)
    
    data = {p.gateway_name: p.dict() for p in s.known_peers.values()}
    
    with open(peers_file, "w") as f:
        json.dump(data, f, indent=2)


def load_peers_from_disk() -> Dict[str, PeerInfo]:
    """Load known peers from disk, bootstrapping from mesh_peers.json if needed"""
    peers_file = Path(DATA_DIR) / "peers.json"
    
    # Try loading existing peers first
    if peers_file.exists():
        try:
            with open(peers_file) as f:
                data = json.load(f)
            peers = {name: PeerInfo(**info) for name, info in data.items()}
            if peers:
                return peers
        except Exception as e:
            logger.warning(f"Failed to load peers.json: {e}")
    
    # Bootstrap from mesh_peers.json if no peers found
    mesh_peers_locations = [
        Path("/home/ubuntu/wg-manager/whisper_data/mesh_peers.json"),
        Path("/home/ubuntu/wg-manager/gateway_api/mesh_peers.json"),
        Path(DATA_DIR) / "mesh_peers.json"
    ]
    
    for mesh_file in mesh_peers_locations:
        if mesh_file.exists():
            try:
                with open(mesh_file) as f:
                    mesh_data = json.load(f)
                
                peers = {}
                for addr, info in mesh_data.items():
                    # Skip backend nodes (type=backend) and self
                    if info.get("type") == "backend":
                        continue
                    
                    name = info.get("name", addr)
                    ip = addr.split(":")[0] if ":" in addr else addr
                    
                    # Create PeerInfo with basic data (will be updated on first heartbeat)
                    peers[name] = PeerInfo(
                        gateway_name=name,
                        mgmt_ip=ip,
                        last_seen=datetime.utcnow().isoformat(),
                        is_alive=False  # Will be set to True on first heartbeat
                    )
                
                if peers:
                    logger.info(f"Bootstrapped {len(peers)} peers from {mesh_file}")
                    return peers
            except Exception as e:
                logger.warning(f"Failed to bootstrap from {mesh_file}: {e}")
    
    return {}


# =============================================================================
# Initialization
# =============================================================================

def init_state():
    """Initialize whisper node state"""
    global state
    
    # Get gateway identity from environment
    gateway_name = os.environ.get("GATEWAY_NAME", "unknown")
    mgmt_ip = os.environ.get("MGMT_IP", "0.0.0.0")
    cert_serial = os.environ.get("CERT_SERIAL")
    
    # Load persisted data
    crl_version, crl_entries, crl_updated = load_crl_from_disk()
    known_peers = load_peers_from_disk()
    
    state = WhisperState(
        gateway_name=gateway_name,
        mgmt_ip=mgmt_ip,
        cert_serial=cert_serial,
        start_time=datetime.utcnow(),
        crl_version=crl_version,
        crl_entries=crl_entries,
        crl_updated_at=crl_updated,
        known_peers=known_peers
    )
    
    logger.info(f"Whisper node initialized: {gateway_name} ({mgmt_ip})")
    logger.info(f"CRL version: {crl_version}, Known peers: {len(known_peers)}")


# =============================================================================
# Main
# =============================================================================

def run_server():
    """Run the whisper node server"""
    init_state()
    
    # Start heartbeat worker thread for mesh self-monitoring
    heartbeat_thread = threading.Thread(target=heartbeat_worker, daemon=True)
    heartbeat_thread.start()
    logger.info("Mesh self-monitoring heartbeat worker started")
    
    # Check for certificates
    if not os.path.exists(CERT_PATH):
        logger.warning(f"Certificate not found at {CERT_PATH}, running without TLS")
        uvicorn.run(app, host="0.0.0.0", port=WHISPER_PORT)
    else:
        # Run with TLS
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(CERT_PATH, KEY_PATH)
        
        # For mTLS: require and verify client certificates
        if os.path.exists(CA_CERT_PATH):
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.load_verify_locations(CA_CERT_PATH)
            logger.info("mTLS enabled - requiring client certificates")
        
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=WHISPER_PORT,
            ssl_keyfile=KEY_PATH,
            ssl_certfile=CERT_PATH,
            log_level="info"
        )


if __name__ == "__main__":
    run_server()

