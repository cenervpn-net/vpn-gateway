#!/usr/bin/env python3
"""
Mesh Peer Synchronization Service

Handles the lifecycle of peer configuration sync with the Whisper mesh:
1. Broadcasting peer configs to mesh on create/update
2. Recovering peer configs during reprovisioning
3. Quorum verification for recovery

Security Model:
- Identity derived from WG private keys (volatile, gateway-unique)
- Peer configs encrypted before broadcast
- Quorum of mesh peers must agree on recovery data
- Backend never sees peer configs (zero-knowledge)

Author: CenterVPN
Created: January 7, 2026
"""

import os
import json
import asyncio
import logging
import hashlib
import ssl
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass

import httpx

from peer_recovery_crypto import (
    PeerRecoveryCrypto,
    MeshIdentity,
    EncryptedPeerBlob,
    WrappedKeyBundle,
    RecoveryRequest,
    load_wg_private_keys,
    hash_peer_config
)

logger = logging.getLogger("mesh_peer_sync")

# Configuration
DEFAULT_WHISPER_PORT = 8100  # Default port for gateway mesh peers
QUORUM_SIZE = 2  # Minimum peers that must agree
MAX_RECOVERY_PEERS = 5  # Max peers to query for recovery
RECOVERY_TIMEOUT = 30  # Seconds


def parse_peer_address(addr: str) -> Tuple[str, int]:
    """
    Parse peer address which may be 'ip' or 'ip:port'.
    Backend mesh nodes use custom ports (8101, 8102).
    
    Returns:
        Tuple of (ip, port)
    """
    if ':' in addr:
        parts = addr.rsplit(':', 1)
        return parts[0], int(parts[1])
    return addr, DEFAULT_WHISPER_PORT


@dataclass
class QuorumResult:
    """Result of quorum verification"""
    achieved: bool
    agreeing_peers: List[str]
    disagreeing_peers: List[str]
    consensus_hash: Optional[str]
    total_queried: int
    errors: List[str]


@dataclass
class RecoveryResult:
    """Result of peer config recovery"""
    success: bool
    recovered_configs: List[dict]
    quorum: QuorumResult
    identity_pubkey: str
    message: str


class MeshPeerSync:
    """
    Manages peer configuration synchronization with the Whisper mesh.
    
    Usage:
        sync = MeshPeerSync()
        await sync.initialize()  # Derives identity from WG keys
        
        # On peer creation
        await sync.broadcast_peer_config(peer_config)
        
        # On reprovision (after reboot in RAM-only mode)
        result = await sync.recover_peer_configs()
    """
    
    def __init__(self, cert_path: str = None, key_path: str = None, ca_path: str = None):
        self.crypto = PeerRecoveryCrypto()
        self.identity: Optional[MeshIdentity] = None
        
        # TLS paths for mTLS connections to mesh peers
        self.cert_path = cert_path or os.environ.get("WHISPER_CERT", "/home/ubuntu/wg-manager/gateway_api/cert.pem")
        self.key_path = key_path or os.environ.get("WHISPER_KEY", "/home/ubuntu/wg-manager/gateway_api/key.pem")
        self.ca_path = ca_path or os.environ.get("WHISPER_CA", "/home/ubuntu/wg-manager/gateway_api/ca.crt")
        
        # Data directory for tracking
        self.data_dir = Path(os.environ.get("WHISPER_DATA", "/dev/shm/whisper_data"))
        
        # Peer list (loaded from whisper state)
        self._mesh_peers: Dict[str, dict] = {}  # ip -> {pubkey, name, ...}
        self._config_version = 0
        
    async def initialize(self) -> bool:
        """
        Initialize the sync service by deriving identity from WG keys.
        
        Returns:
            True if initialization successful
        """
        try:
            # Load WG private keys
            wg_keys = load_wg_private_keys()
            if not wg_keys:
                logger.error("No WG private keys found - cannot initialize mesh sync")
                return False
            
            # Derive identity
            self.identity = self.crypto.derive_identity(wg_keys)
            logger.info(f"Mesh sync initialized with identity: {self.identity.public_key_b64()[:16]}...")
            
            # Load config version
            self._load_config_version()
            
            return True
        except Exception as e:
            logger.error(f"Failed to initialize mesh sync: {e}")
            return False
    
    def _load_config_version(self):
        """Load the current config version from disk"""
        version_file = self.data_dir / "config_version.txt"
        if version_file.exists():
            try:
                self._config_version = int(version_file.read_text().strip())
            except:
                self._config_version = 0
    
    def _save_config_version(self):
        """Save the current config version to disk"""
        version_file = self.data_dir / "config_version.txt"
        version_file.parent.mkdir(parents=True, exist_ok=True)
        version_file.write_text(str(self._config_version))
    
    def _get_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for mTLS connections"""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.load_cert_chain(self.cert_path, self.key_path)
        ctx.load_verify_locations(self.ca_path)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx
    
    async def _get_mesh_peers(self) -> Dict[str, dict]:
        """
        Get list of mesh peers with their public keys.
        
        Returns:
            Dict mapping IP -> {pubkey, name}
        """
        # Try to load from whisper state file
        peers_file = self.data_dir / "mesh_peers.json"
        if peers_file.exists():
            try:
                with open(peers_file) as f:
                    self._mesh_peers = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load mesh peers: {e}")
        
        # Also try to get from local whisper node
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                resp = await client.get("http://localhost:8100/whisper/status")
                if resp.status_code == 200:
                    data = resp.json()
                    for peer in data.get("known_peers", []):
                        ip = peer.get("ip", peer.get("mgmt_ip"))
                        if ip:
                            self._mesh_peers[ip] = {
                                "name": peer.get("name", peer.get("gateway_name")),
                                "pubkey": peer.get("identity_pubkey", ""),  # May not have yet
                                "status": peer.get("status", "unknown")
                            }
        except Exception as e:
            logger.debug(f"Could not get peers from local whisper: {e}")
        
        return self._mesh_peers
    
    async def broadcast_peer_config(
        self,
        peer_config: dict,
        mesh_peers: Dict[str, str] = None
    ) -> Tuple[int, int]:
        """
        Broadcast an encrypted peer config to all mesh peers.
        
        Args:
            peer_config: The peer configuration dict
            mesh_peers: Optional dict of peer_ip -> identity_pubkey
        
        Returns:
            Tuple of (success_count, total_count)
        """
        if not self.identity:
            raise RuntimeError("Mesh sync not initialized")
        
        # Get mesh peers if not provided
        if not mesh_peers:
            await self._get_mesh_peers()
            # Include gateway peers with pubkeys AND backend peers (no pubkey required)
            mesh_peers = {}
            for ip, info in self._mesh_peers.items():
                if info.get("type") == "backend":
                    # Backend nodes use a placeholder identity (they store blobs as-is)
                    mesh_peers[ip] = info.get("name", f"backend-{ip}")
                elif info.get("pubkey"):
                    mesh_peers[ip] = info.get("pubkey")
            
            # Note: For self-recovery via backend nodes, the sender's wrapped_key
            # is included in the blob by the crypto layer during encryption
        
        if not mesh_peers:
            logger.warning("No mesh peers configured - skipping broadcast")
            return 0, 0
        
        # Increment version
        self._config_version += 1
        self._save_config_version()
        
        # Encrypt peer config
        blob, wrapped_keys = self.crypto.encrypt_peer_config(
            peer_config,
            mesh_peers,
            version=self._config_version
        )
        
        # Broadcast to all peers
        success_count = 0
        total_count = len(mesh_peers)
        
        # Generate peer_id for status lookups (hash of public_key)
        peer_public_key = peer_config.get("public_key", "")
        config_peer_id = hash_peer_config({"public_key": peer_public_key})
        
        ssl_ctx = self._get_ssl_context()
        
        async def send_to_peer(addr: str, mesh_peer_id: str):
            nonlocal success_count
            try:
                ip, port = parse_peer_address(addr)
                
                # Check if this is a backend node (stores blobs as-is, no decryption)
                is_backend = self._mesh_peers.get(addr, {}).get("type") == "backend"
                
                if is_backend:
                    # Backend nodes store blobs for recovery - include sender's wrapped key
                    # so the sender can recover their own blobs later
                    my_pubkey = self.identity.public_key_b64()
                    my_wrapped_key = wrapped_keys.get(my_pubkey)
                    payload = {
                        "identity_pubkey": my_pubkey,
                        "blob_hash": blob.blob_hash,
                        "encrypted_blob": blob.encrypted_data,
                        "blob_nonce": blob.nonce,
                        "version": blob.version,
                        "wrapped_key": my_wrapped_key.wrapped_key if my_wrapped_key else "",
                        "wrapped_key_nonce": my_wrapped_key.nonce if my_wrapped_key else "",
                        "timestamp": blob.timestamp,
                        "signature": "",
                        "peer_id": config_peer_id  # For status lookups
                    }
                else:
                    # Gateway nodes need wrapped keys for decryption
                    if mesh_peer_id not in wrapped_keys:
                        logger.warning(f"No wrapped key for peer {mesh_peer_id}")
                        return
                    
                    wk = wrapped_keys[mesh_peer_id]
                    payload = {
                        "identity_pubkey": self.identity.public_key_b64(),
                        "blob_hash": blob.blob_hash,
                        "encrypted_blob": blob.encrypted_data,
                        "blob_nonce": blob.nonce,
                        "version": blob.version,
                        "wrapped_key": wk.wrapped_key,
                        "wrapped_key_nonce": wk.nonce,
                        "timestamp": blob.timestamp,
                        "signature": "",
                        "peer_id": config_peer_id  # For status lookups
                    }
                
                # Use HTTP for backend mesh nodes (no mTLS), HTTPS for gateways
                protocol = "http" if is_backend else "https"
                client_ctx = None if is_backend else ssl_ctx
                
                async with httpx.AsyncClient(verify=client_ctx, timeout=10.0) as client:
                    resp = await client.post(
                        f"{protocol}://{ip}:{port}/whisper/peer-data/store",
                        json=payload
                    )
                    if resp.status_code == 200:
                        success_count += 1
                        logger.debug(f"Broadcast to {addr} successful")
                    else:
                        logger.warning(f"Broadcast to {addr} failed: {resp.status_code}")
            except Exception as e:
                logger.warning(f"Failed to broadcast to {addr}: {e}")
        
        # Send in parallel
        tasks = [send_to_peer(ip, ip) for ip in mesh_peers.keys()]
        await asyncio.gather(*tasks)
        
        logger.info(f"Broadcast peer config v{self._config_version} to {success_count}/{total_count} peers")
        return success_count, total_count
    
    async def recover_peer_configs(self, require_quorum: bool = True) -> RecoveryResult:
        """
        Recover peer configs from the mesh after reboot.
        
        This queries multiple mesh peers, verifies quorum agreement,
        and decrypts the peer configurations.
        
        Args:
            require_quorum: Whether to require quorum (set False for testing)
        
        Returns:
            RecoveryResult with recovered configs
        """
        if not self.identity:
            raise RuntimeError("Mesh sync not initialized")
        
        # Get mesh peers
        await self._get_mesh_peers()
        # Include backend mesh nodes (status: "persistent") and gateway peers
        alive_peers = [addr for addr, info in self._mesh_peers.items() 
                       if info.get("status") in ("alive", "unknown", "persistent", None)]
        
        if len(alive_peers) < QUORUM_SIZE and require_quorum:
            return RecoveryResult(
                success=False,
                recovered_configs=[],
                quorum=QuorumResult(
                    achieved=False,
                    agreeing_peers=[],
                    disagreeing_peers=[],
                    consensus_hash=None,
                    total_queried=0,
                    errors=[f"Not enough peers ({len(alive_peers)} < {QUORUM_SIZE})"]
                ),
                identity_pubkey=self.identity.public_key_b64(),
                message="Not enough mesh peers for quorum"
            )
        
        # Create signed recovery request
        request = self.crypto.create_recovery_request()
        
        # Query peers in parallel
        responses: Dict[str, dict] = {}
        errors: List[str] = []
        
        ssl_ctx = self._get_ssl_context()
        
        async def query_peer(addr: str):
            try:
                ip, port = parse_peer_address(addr)
                is_backend = self._mesh_peers.get(addr, {}).get("type") == "backend"
                protocol = "http" if is_backend else "https"
                client_ctx = None if is_backend else ssl_ctx
                
                async with httpx.AsyncClient(verify=client_ctx, timeout=RECOVERY_TIMEOUT) as client:
                    resp = await client.post(
                        f"{protocol}://{ip}:{port}/whisper/peer-data/recover",
                        json=request.to_dict()
                    )
                    if resp.status_code == 200:
                        responses[addr] = resp.json()
                    else:
                        errors.append(f"{addr}: HTTP {resp.status_code}")
            except Exception as e:
                errors.append(f"{addr}: {str(e)}")
        
        # Query up to MAX_RECOVERY_PEERS
        peers_to_query = alive_peers[:MAX_RECOVERY_PEERS]
        tasks = [query_peer(ip) for ip in peers_to_query]
        await asyncio.gather(*tasks)
        
        # Verify quorum - peers must agree on blob hashes
        quorum_result = self._verify_quorum(responses)
        
        if require_quorum and not quorum_result.achieved:
            return RecoveryResult(
                success=False,
                recovered_configs=[],
                quorum=quorum_result,
                identity_pubkey=self.identity.public_key_b64(),
                message="Quorum not achieved"
            )
        
        # Decrypt configs from first agreeing peer's response
        recovered_configs = []
        
        if quorum_result.agreeing_peers:
            first_peer = quorum_result.agreeing_peers[0]
            peer_response = responses[first_peer]
            
            if peer_response.get("status") == "ok" and peer_response.get("blobs"):
                try:
                    recovered_configs = self._decrypt_blobs(
                        peer_response["blobs"],
                        peer_response.get("wrapped_key"),
                        peer_response.get("wrapped_key_nonce"),
                        first_peer
                    )
                except Exception as e:
                    logger.error(f"Failed to decrypt blobs: {e}")
                    errors.append(f"Decryption failed: {e}")
        
        return RecoveryResult(
            success=len(recovered_configs) > 0,
            recovered_configs=recovered_configs,
            quorum=quorum_result,
            identity_pubkey=self.identity.public_key_b64(),
            message=f"Recovered {len(recovered_configs)} peer configs"
        )
    
    def _verify_quorum(self, responses: Dict[str, dict]) -> QuorumResult:
        """
        Verify quorum agreement among peer responses.
        
        Peers must agree on the set of blob hashes.
        """
        if not responses:
            return QuorumResult(
                achieved=False,
                agreeing_peers=[],
                disagreeing_peers=[],
                consensus_hash=None,
                total_queried=0,
                errors=["No responses received"]
            )
        
        # Build hash of blob hashes per peer
        peer_hashes: Dict[str, str] = {}
        
        for ip, resp in responses.items():
            if resp.get("status") == "ok" and resp.get("blobs"):
                # Hash of all blob hashes (sorted for determinism)
                blob_hashes = sorted([b["blob_hash"] for b in resp["blobs"]])
                combined = "|".join(blob_hashes)
                peer_hashes[ip] = hashlib.sha256(combined.encode()).hexdigest()
            elif resp.get("status") == "not_found":
                peer_hashes[ip] = "NOT_FOUND"
            else:
                peer_hashes[ip] = "ERROR"
        
        # Find most common hash
        hash_counts: Dict[str, List[str]] = {}
        for ip, h in peer_hashes.items():
            if h not in hash_counts:
                hash_counts[h] = []
            hash_counts[h].append(ip)
        
        # Get consensus (most common)
        consensus_hash = max(hash_counts.keys(), key=lambda h: len(hash_counts[h]))
        agreeing_peers = hash_counts[consensus_hash]
        disagreeing_peers = [ip for ip in peer_hashes.keys() if ip not in agreeing_peers]
        
        achieved = len(agreeing_peers) >= QUORUM_SIZE and consensus_hash not in ("NOT_FOUND", "ERROR")
        
        return QuorumResult(
            achieved=achieved,
            agreeing_peers=agreeing_peers,
            disagreeing_peers=disagreeing_peers,
            consensus_hash=consensus_hash if achieved else None,
            total_queried=len(responses),
            errors=[]
        )
    
    def _decrypt_blobs(
        self,
        blobs: List[dict],
        wrapped_key: str,
        wrapped_key_nonce: str,
        peer_ip: str
    ) -> List[dict]:
        """Decrypt peer config blobs"""
        if not wrapped_key:
            raise ValueError("No wrapped key provided")
        
        # Get peer's public key for ECDH
        peer_info = self._mesh_peers.get(peer_ip, {})
        is_backend = peer_info.get("type") == "backend"
        
        if is_backend:
            # Backend nodes store our wrapped key for ourselves
            # Use our own public key for decryption
            peer_pubkey = self.identity.public_key_b64()
        else:
            peer_pubkey = peer_info.get("pubkey")
        
        if not peer_pubkey:
            raise ValueError(f"No public key for peer {peer_ip}")
        
        configs = []
        
        for blob_dict in blobs:
            try:
                blob = EncryptedPeerBlob(
                    blob_hash=blob_dict["blob_hash"],
                    encrypted_data=blob_dict["encrypted_blob"],
                    nonce=blob_dict["blob_nonce"],
                    version=blob_dict["version"],
                    timestamp=blob_dict["timestamp"],
                    owner_identity=self.identity.public_key_b64()
                )
                
                # Use per-blob wrapped key if available, otherwise fall back to identity-level
                blob_wrapped_key = blob_dict.get("wrapped_key") or wrapped_key
                blob_wrapped_key_nonce = blob_dict.get("wrapped_key_nonce") or wrapped_key_nonce
                
                if not blob_wrapped_key:
                    logger.warning(f"No wrapped key for blob {blob_dict.get('blob_hash', 'unknown')[:8]}")
                    continue
                
                wk = WrappedKeyBundle(
                    peer_pubkey_hash="",  # Not needed for decryption
                    wrapped_key=blob_wrapped_key,
                    nonce=blob_wrapped_key_nonce
                )
                
                config = self.crypto.decrypt_peer_config(blob, wk, peer_pubkey)
                
                # Override status with storage-level status (reflects suspend/resume)
                storage_status = blob_dict.get("status", "active")
                config["status"] = storage_status
                logger.debug(f"Decrypted blob {blob_dict.get('blob_hash', '')[:8]}... with status={storage_status}")
                
                configs.append(config)
            except Exception as e:
                logger.warning(f"Failed to decrypt blob {blob_dict.get('blob_hash', 'unknown')[:8]}: {e}")
        
        return configs
    
    async def purge_peer_blob(self, peer_public_key: str) -> Tuple[int, int]:
        """
        Purge a specific peer's blob from all mesh peers (on peer deletion).
        
        This removes the actual data instead of creating tombstones,
        preventing accumulation and ghost peer recovery.
        
        Args:
            peer_public_key: The WireGuard public key of the deleted peer
        
        Returns:
            Tuple of (success_count, total_count)
        """
        if not self.identity:
            raise RuntimeError("Mesh sync not initialized")
        
        await self._get_mesh_peers()
        
        # Use peer_id for reliable lookup (hash of public_key only)
        # This matches how blobs are stored with peer_id field
        peer_id = hash_peer_config({"public_key": peer_public_key})
        
        success_count = 0
        total_count = len(self._mesh_peers)
        
        ssl_ctx = self._get_ssl_context()
        
        async def purge_from_peer(addr: str):
            nonlocal success_count
            try:
                ip, port = parse_peer_address(addr)
                is_backend = self._mesh_peers.get(addr, {}).get("type") == "backend"
                protocol = "http" if is_backend else "https"
                client_ctx = None if is_backend else ssl_ctx
                
                payload = {
                    "identity_pubkey": self.identity.public_key_b64(),
                    "peer_id": peer_id,  # Use peer_id for reliable lookup
                    "peer_public_key": peer_public_key,
                    "reason": "peer_deleted",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                async with httpx.AsyncClient(verify=client_ctx, timeout=10.0) as client:
                    resp = await client.post(
                        f"{protocol}://{ip}:{port}/whisper/peer-data/purge-blob",
                        json=payload
                    )
                    if resp.status_code == 200:
                        result = resp.json()
                        if result.get("status") == "purged":
                            success_count += 1
                            logger.debug(f"Purged peer blob from {addr}")
                        else:
                            logger.debug(f"Blob not found on {addr}")
                    else:
                        logger.warning(f"Failed to purge from {addr}: HTTP {resp.status_code}")
            except Exception as e:
                logger.warning(f"Failed to purge from {addr}: {e}")
        
        tasks = [purge_from_peer(ip) for ip in self._mesh_peers.keys()]
        await asyncio.gather(*tasks)
        
        logger.info(f"Purged peer blob (peer_id: {peer_id[:8]}...) from {success_count}/{total_count} mesh peers")
        return success_count, total_count

    async def purge_data_from_mesh(self, reason: str = "wipe") -> Tuple[int, int]:
        """
        Purge ALL our data from all mesh peers (on gateway wipe/delete).
        
        Args:
            reason: "wipe" or "delete"
        
        Returns:
            Tuple of (success_count, total_count)
        """
        if not self.identity:
            raise RuntimeError("Mesh sync not initialized")
        
        await self._get_mesh_peers()
        
        success_count = 0
        total_count = len(self._mesh_peers)
        
        ssl_ctx = self._get_ssl_context()
        
        async def purge_from_peer_all(addr: str):
            nonlocal success_count
            try:
                ip, port = parse_peer_address(addr)
                is_backend = self._mesh_peers.get(addr, {}).get("type") == "backend"
                protocol = "http" if is_backend else "https"
                client_ctx = None if is_backend else ssl_ctx
                
                payload = {
                    "identity_pubkey": self.identity.public_key_b64(),
                    "reason": reason,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "backend_signature": ""  # TODO: Backend signature
                }
                
                async with httpx.AsyncClient(verify=client_ctx, timeout=10.0) as client:
                    resp = await client.post(
                        f"{protocol}://{ip}:{port}/whisper/peer-data/purge",
                        json=payload
                    )
                    if resp.status_code == 200:
                        success_count += 1
                        logger.info(f"Purged data from {addr}")
            except Exception as e:
                logger.warning(f"Failed to purge from {addr}: {e}")
        
        tasks = [purge_from_peer_all(addr) for addr in self._mesh_peers.keys()]
        await asyncio.gather(*tasks)
        
        logger.info(f"Purged data from {success_count}/{total_count} mesh peers")
        return success_count, total_count

    async def update_peer_status(
        self,
        peer_public_key: str,
        new_status: str  # "active" or "suspended"
    ) -> Tuple[int, int]:
        """
        Update the status of a peer blob across all mesh peers.
        
        Used for suspend/resume operations:
        - Suspend: status = "suspended"
        - Resume: status = "active"
        
        Args:
            peer_public_key: The WireGuard public key of the peer
            new_status: "active" or "suspended"
        
        Returns:
            Tuple of (success_count, total_count)
        """
        if not self.identity:
            raise RuntimeError("Mesh sync not initialized")
        
        await self._get_mesh_peers()
        
        # Hash the peer config to get peer_id for status lookups
        peer_id = hash_peer_config({"public_key": peer_public_key})
        
        success_count = 0
        total_count = len(self._mesh_peers)
        
        ssl_ctx = self._get_ssl_context()
        
        async def update_on_peer(addr: str):
            nonlocal success_count
            try:
                ip, port = parse_peer_address(addr)
                is_backend = self._mesh_peers.get(addr, {}).get("type") == "backend"
                protocol = "http" if is_backend else "https"
                client_ctx = None if is_backend else ssl_ctx
                
                payload = {
                    "identity_pubkey": self.identity.public_key_b64(),
                    "peer_id": peer_id,  # Use peer_id for lookup
                    "status": new_status,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                async with httpx.AsyncClient(verify=client_ctx, timeout=10.0) as client:
                    resp = await client.patch(
                        f"{protocol}://{ip}:{port}/whisper/peer-data/status",
                        json=payload
                    )
                    if resp.status_code == 200:
                        success_count += 1
                        logger.debug(f"Updated peer status on {addr}")
                    else:
                        logger.warning(f"Failed to update status on {addr}: HTTP {resp.status_code}")
            except Exception as e:
                logger.warning(f"Failed to update status on {addr}: {e}")
        
        tasks = [update_on_peer(addr) for addr in self._mesh_peers.keys()]
        await asyncio.gather(*tasks)
        
        logger.info(f"Updated peer {peer_public_key[:16]}... status to '{new_status}' on {success_count}/{total_count} mesh peers")
        return success_count, total_count

    async def query_peer_from_mesh(
        self,
        peer_public_key: str = "",
        status_filter: str = ""
    ) -> List[dict]:
        """
        Query for specific peer data from the mesh.
        
        Used for resume operations to get suspended peer configs.
        
        Args:
            peer_public_key: Optional WireGuard public key to filter by
            status_filter: Optional status filter ("active", "suspended")
        
        Returns:
            List of matching blobs from mesh peers
        """
        if not self.identity:
            raise RuntimeError("Mesh sync not initialized")
        
        await self._get_mesh_peers()
        
        blob_hash = ""
        if peer_public_key:
            blob_hash = hash_peer_config({"public_key": peer_public_key})
        
        ssl_ctx = self._get_ssl_context()
        results: List[dict] = []
        
        async def query_peer(addr: str):
            try:
                ip, port = parse_peer_address(addr)
                is_backend = self._mesh_peers.get(addr, {}).get("type") == "backend"
                protocol = "http" if is_backend else "https"
                client_ctx = None if is_backend else ssl_ctx
                
                payload = {
                    "identity_pubkey": self.identity.public_key_b64(),
                    "peer_public_key": peer_public_key,
                    "blob_hash": blob_hash,
                    "status_filter": status_filter
                }
                
                async with httpx.AsyncClient(verify=client_ctx, timeout=10.0) as client:
                    resp = await client.post(
                        f"{protocol}://{ip}:{port}/whisper/peer-data/query",
                        json=payload
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("status") == "ok" and data.get("blobs"):
                            return {
                                "peer": addr,
                                "blobs": data["blobs"],
                                "wrapped_key": data.get("wrapped_key"),
                                "wrapped_key_nonce": data.get("wrapped_key_nonce")
                            }
            except Exception as e:
                logger.debug(f"Query to {addr} failed: {e}")
            return None
        
        tasks = [query_peer(addr) for addr in self._mesh_peers.keys()]
        responses = await asyncio.gather(*tasks)
        
        results = [r for r in responses if r is not None]
        logger.info(f"Query returned results from {len(results)} mesh peers")
        return results


# =============================================================================
# Integration with Gateway API
# =============================================================================

# Global instance (initialized on gateway startup)
_mesh_sync: Optional[MeshPeerSync] = None


async def get_mesh_sync() -> MeshPeerSync:
    """Get or create the global MeshPeerSync instance"""
    global _mesh_sync
    if _mesh_sync is None:
        _mesh_sync = MeshPeerSync()
        await _mesh_sync.initialize()
    return _mesh_sync


async def on_peer_created(peer_config: dict):
    """Called when a new peer is provisioned - broadcast to mesh"""
    try:
        sync = await get_mesh_sync()
        await sync.broadcast_peer_config(peer_config)
    except Exception as e:
        logger.error(f"Failed to broadcast peer config: {e}")


async def on_peer_updated(peer_config: dict):
    """Called when a peer config is updated - broadcast to mesh"""
    try:
        sync = await get_mesh_sync()
        await sync.broadcast_peer_config(peer_config)
    except Exception as e:
        logger.error(f"Failed to broadcast peer update: {e}")


async def on_peer_deleted(peer_public_key: str):
    """Called when a peer is deleted - purge blob from all mesh peers"""
    # Instead of tombstones, we purge the actual blob data
    # This prevents accumulation and ghost peer recovery
    try:
        sync = await get_mesh_sync()
        await sync.purge_peer_blob(peer_public_key)
    except Exception as e:
        logger.error(f"Failed to purge peer blob from mesh: {e}")


async def on_peer_suspended(peer_public_key: str):
    """Called when a peer is suspended - update status in mesh"""
    try:
        sync = await get_mesh_sync()
        await sync.update_peer_status(peer_public_key, "suspended")
    except Exception as e:
        logger.error(f"Failed to update peer status in mesh: {e}")


async def on_peer_resumed(peer_public_key: str):
    """Called when a peer is resumed - update status in mesh"""
    try:
        sync = await get_mesh_sync()
        await sync.update_peer_status(peer_public_key, "active")
    except Exception as e:
        logger.error(f"Failed to update peer status in mesh: {e}")


async def query_suspended_peer(peer_public_key: str) -> Optional[dict]:
    """
    Query for a suspended peer's DECRYPTED config from the mesh.
    Used during resume to recover config if not in local DB.
    
    Returns:
        The decrypted peer config dict if found, None otherwise
    """
    try:
        sync = await get_mesh_sync()
        results = await sync.query_peer_from_mesh(peer_public_key, status_filter="suspended")
        
        if not results:
            logger.debug(f"No suspended peer found in mesh for {peer_public_key[:16]}...")
            return None
        
        # Get the first result with blobs
        for result in results:
            if result.get("blobs"):
                # Decrypt the blob to get the actual config
                try:
                    blobs = result["blobs"]
                    wrapped_key = result.get("wrapped_key")
                    wrapped_key_nonce = result.get("wrapped_key_nonce")
                    peer_addr = result.get("peer")
                    
                    if not wrapped_key:
                        logger.warning("No wrapped key in query result")
                        continue
                    
                    # Decrypt the first matching blob
                    decrypted_configs = sync._decrypt_blobs(
                        blobs, wrapped_key, wrapped_key_nonce, peer_addr
                    )
                    
                    if decrypted_configs:
                        logger.info(f"Decrypted suspended peer config from mesh: {peer_public_key[:16]}...")
                        return decrypted_configs[0]
                        
                except Exception as e:
                    logger.warning(f"Failed to decrypt blob from {result.get('peer')}: {e}")
                    continue
        
        return None
    except Exception as e:
        logger.error(f"Failed to query suspended peer from mesh: {e}")
        return None


async def recover_peers() -> RecoveryResult:
    """Called during reprovisioning to recover peer configs"""
    sync = await get_mesh_sync()
    return await sync.recover_peer_configs()

