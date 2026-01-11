"""
RAM-Only Peer Store

Thread-safe in-memory storage for peer configurations.
Replaces SQLite database for true RAM-only gateway operation.

The mesh network serves as the persistent source of truth.
This in-memory store is populated from mesh on startup and
maintained in sync during runtime.
"""

import logging
from threading import RLock
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class PeerConfig:
    """In-memory representation of a peer configuration"""
    public_key: str
    status: str = "active"  # active, suspended
    assigned_ip: str = ""
    assigned_ipv6: str = ""
    assigned_port: int = 0
    tunnel_traffic: Any = "all"
    dns_choice: str = ""
    allowed_ips: str = ""
    obfuscation_level: str = "off"
    obfuscation_enabled: bool = False
    junk_packet_count: int = 0
    junk_packet_min_size: int = 0
    junk_packet_max_size: int = 0
    init_packet_junk_size: int = 0
    response_packet_junk_size: int = 0
    underload_packet_junk_size: int = 0
    transport_packet_junk_size: int = 0
    init_packet_magic_header: int = 0
    response_packet_magic_header: int = 0
    underload_packet_magic_header: int = 0
    transport_packet_magic_header: int = 0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'PeerConfig':
        """Create from dictionary (handles extra fields gracefully)"""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


class PeerStore:
    """
    Thread-safe in-memory peer configuration store.
    
    This replaces SQLite for RAM-only operation.
    All peer data lives in memory and is synced with the mesh.
    """
    
    def __init__(self):
        self._lock = RLock()
        self._peers: Dict[str, PeerConfig] = {}
        self._ip_allocation: Dict[str, str] = {}  # ip -> public_key
        self._initialized = False
    
    def initialize(self):
        """Mark store as initialized (after mesh recovery)"""
        self._initialized = True
        logger.info(f"PeerStore initialized with {len(self._peers)} peers")
    
    @property
    def is_initialized(self) -> bool:
        return self._initialized
    
    # =========================================================================
    # CRUD Operations
    # =========================================================================
    
    def add(self, peer: PeerConfig) -> bool:
        """Add a new peer to the store"""
        with self._lock:
            if peer.public_key in self._peers:
                logger.warning(f"Peer already exists: {peer.public_key[:20]}...")
                return False
            
            self._peers[peer.public_key] = peer
            
            # Track IP allocation
            if peer.assigned_ip:
                self._ip_allocation[peer.assigned_ip] = peer.public_key
            if peer.assigned_ipv6:
                self._ip_allocation[peer.assigned_ipv6] = peer.public_key
            
            logger.debug(f"Added peer: {peer.public_key[:20]}... status={peer.status}")
            return True
    
    def get(self, public_key: str) -> Optional[PeerConfig]:
        """Get a peer by public key"""
        with self._lock:
            # Try exact match first
            if public_key in self._peers:
                return self._peers[public_key]
            
            # Try with leading slash (base64 edge case)
            if "/" + public_key in self._peers:
                return self._peers["/" + public_key]
            
            return None
    
    def update(self, public_key: str, **kwargs) -> bool:
        """Update peer fields"""
        with self._lock:
            peer = self.get(public_key)
            if not peer:
                return False
            
            for key, value in kwargs.items():
                if hasattr(peer, key):
                    setattr(peer, key, value)
            
            return True
    
    def delete(self, public_key: str) -> bool:
        """Remove a peer from the store"""
        with self._lock:
            peer = self.get(public_key)
            if not peer:
                return False
            
            # Free IP allocation
            if peer.assigned_ip and peer.assigned_ip in self._ip_allocation:
                del self._ip_allocation[peer.assigned_ip]
            if peer.assigned_ipv6 and peer.assigned_ipv6 in self._ip_allocation:
                del self._ip_allocation[peer.assigned_ipv6]
            
            # Remove from store
            actual_key = public_key if public_key in self._peers else "/" + public_key
            if actual_key in self._peers:
                del self._peers[actual_key]
                logger.debug(f"Deleted peer: {public_key[:20]}...")
                return True
            
            return False
    
    def exists(self, public_key: str) -> bool:
        """Check if peer exists"""
        return self.get(public_key) is not None
    
    # =========================================================================
    # Bulk Operations
    # =========================================================================
    
    def get_all(self) -> List[PeerConfig]:
        """Get all peers"""
        with self._lock:
            return list(self._peers.values())
    
    def get_by_status(self, status: str) -> List[PeerConfig]:
        """Get peers by status"""
        with self._lock:
            return [p for p in self._peers.values() if p.status == status]
    
    def count(self, status: Optional[str] = None) -> int:
        """Count peers, optionally filtered by status"""
        with self._lock:
            if status:
                return len([p for p in self._peers.values() if p.status == status])
            return len(self._peers)
    
    def clear(self):
        """Clear all peers (for testing/reset)"""
        with self._lock:
            self._peers.clear()
            self._ip_allocation.clear()
            self._initialized = False
    
    # =========================================================================
    # IP Allocation
    # =========================================================================
    
    def is_ip_used(self, ip: str) -> bool:
        """Check if an IP is already allocated"""
        with self._lock:
            return ip in self._ip_allocation
    
    def get_used_ips(self) -> List[str]:
        """Get list of all used IPs"""
        with self._lock:
            return list(self._ip_allocation.keys())
    
    def allocate_ip(self, ip: str, public_key: str):
        """Manually allocate an IP to a peer"""
        with self._lock:
            self._ip_allocation[ip] = public_key
    
    def free_ip(self, ip: str):
        """Free an IP allocation"""
        with self._lock:
            if ip in self._ip_allocation:
                del self._ip_allocation[ip]
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def stats(self) -> dict:
        """Get store statistics"""
        with self._lock:
            return {
                "total_peers": len(self._peers),
                "active_peers": len([p for p in self._peers.values() if p.status == "active"]),
                "suspended_peers": len([p for p in self._peers.values() if p.status == "suspended"]),
                "allocated_ips": len(self._ip_allocation),
                "initialized": self._initialized
            }


# Global instance
_peer_store: Optional[PeerStore] = None


def get_peer_store() -> PeerStore:
    """Get or create the global peer store instance"""
    global _peer_store
    if _peer_store is None:
        _peer_store = PeerStore()
    return _peer_store
