import subprocess
import logging
import ipaddress
import os
from typing import Optional, Tuple, List, Dict, Set
from datetime import datetime
from config import get_settings
import threading
from queue import Queue
import time

logger = logging.getLogger(__name__)
settings = get_settings()

MAX_PEERS = 100
BATCH_SIZE = 10  # Process peers in batches
COMMAND_QUEUE = Queue()
RESULT_QUEUE = Queue()

class WireGuardManager:
    def __init__(self):
        self.interface = os.getenv('WG_INTERFACE', 'wg0')
        self.ipv4_subnet = ipaddress.IPv4Network(settings.WG_IPV4_SUBNET)
        self.ipv6_subnet = ipaddress.IPv6Network(settings.WG_IPV6_SUBNET)
        
        # Thread-safe sets for IP management
        self._ip_lock = threading.Lock()
        self.available_ipv4s: Set[str] = set()
        self.available_ipv6s: Set[str] = set()
        self.assigned_ipv4s: Set[str] = set()
        self.assigned_ipv6s: Set[str] = set()
        
        # Get gateway IPs
        self.gateway_ipv4 = str(next(self.ipv4_subnet.hosts()))
        self.gateway_ipv6 = str(next(self.ipv6_subnet.hosts()))
        
        # Pre-generate IP pools
        self._initialize_ip_pools()
        
        # Start command processing thread
        self._start_command_processor()
        
        # Wait for thread to be ready
        time.sleep(0.5)
        
        # Now sync IPs
        self.sync_assigned_ips()

    def _start_command_processor(self):
        """Start a background thread to process WireGuard commands"""
        def process_commands():
            while True:
                try:
                    cmd = COMMAND_QUEUE.get()
                    if cmd is None:  # Shutdown signal
                        break
                    
                    result = subprocess.run(
                        ["/usr/bin/sudo", "/usr/bin/awg"] + cmd,
                        capture_output=True,
                        text=True
                    )
                    RESULT_QUEUE.put((cmd, result))
                    
                except Exception as e:
                    logger.error(f"Command processing error: {e}")
                    RESULT_QUEUE.put((cmd, None))  # Signal failure
                finally:
                    COMMAND_QUEUE.task_done()
        
        self.command_thread = threading.Thread(target=process_commands, daemon=True)
        self.command_thread.start()

    def run_wg_command(self, command: list) -> subprocess.CompletedProcess:
        """Thread-safe command execution"""
        try:
            COMMAND_QUEUE.put(command)
            cmd, result = RESULT_QUEUE.get(timeout=5)  # 5 second timeout
            
            if result is None:
                raise Exception("Command processing failed")
                
            if result.returncode != 0:
                logger.error(f"Command failed: {' '.join(cmd)}")
                logger.error(f"Error output: {result.stderr}")
                raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
            return result
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            logger.error(f"Command was: {' '.join(command)}")
            raise

    def _initialize_ip_pools(self):
        """Pre-generate pools of available IPs for maximum number of peers"""
        with self._ip_lock:
            # IPv4 pool
            ipv4_iter = self.ipv4_subnet.hosts()
            next(ipv4_iter)  # Skip gateway
            for _ in range(MAX_PEERS):
                try:
                    self.available_ipv4s.add(str(next(ipv4_iter)))
                except StopIteration:
                    break

            # IPv6 pool - generate structured addresses
            network = self.ipv6_subnet.network_address
            prefix = str(network).split('::')[0]
            for i in range(1, MAX_PEERS + 1):
                ipv6_addr = f"{prefix}::2:{i:04x}"
                self.available_ipv6s.add(ipv6_addr)

    def generate_ip_addresses(self, protocol: str) -> Tuple[Optional[str], Optional[str]]:
        """Thread-safe IP address generation"""
        with self._ip_lock:
            ipv4 = None
            ipv6 = None

            if protocol in [None, 'ipv4', 'dual']:
                available = self.available_ipv4s - self.assigned_ipv4s
                if not available:
                    raise Exception(f"No IPv4 addresses available. Maximum peers ({MAX_PEERS}) reached")
                ipv4 = min(available)

            if protocol in ['ipv6', 'dual']:
                available = self.available_ipv6s - self.assigned_ipv6s
                if not available:
                    raise Exception(f"No IPv6 addresses available. Maximum peers ({MAX_PEERS}) reached")
                ipv6 = min(available)

            return ipv4, ipv6

    def add_peer(self, public_key, protocol=None, tunnel_traffic=['ipv4'], port=51820, assigned_ipv4=None, assigned_ipv6=None, obfuscation=None):
        """Add a new peer with optimized IP assignment and AmneziaWG obfuscation"""
        try:
            # Ensure tunnel_traffic is not empty
            if not tunnel_traffic:
                tunnel_traffic = ['ipv4']  # Default to IPv4 if tunnel_traffic is empty
                
            # Determine which addresses to assign
            use_ipv4 = 'ipv4' in tunnel_traffic
            use_ipv6 = 'ipv6' in tunnel_traffic
            
            logger.info(f"Adding peer: {public_key} (protocol: {protocol}, tunnel: {tunnel_traffic}, obfuscation: {bool(obfuscation)})")
            
            # Generate IP addresses or reuse previously assigned ones
            if assigned_ipv4 is None and use_ipv4:
                assigned_ipv4, _ = self.generate_ip_addresses('ipv4')
            if assigned_ipv6 is None and use_ipv6:
                _, assigned_ipv6 = self.generate_ip_addresses('ipv6')
            
            # Ensure at least one IP address is assigned
            if not assigned_ipv4 and not assigned_ipv6:
                assigned_ipv4, _ = self.generate_ip_addresses('ipv4')
                
            # Build allowed IPs
            allowed_ips = []
            if assigned_ipv4:
                allowed_ips.append(f"{assigned_ipv4}/32")
            if assigned_ipv6:
                allowed_ips.append(f"{assigned_ipv6}/128")
            
            if not allowed_ips:
                raise Exception("No valid IP addresses assigned")
            
            # Build AWG command with obfuscation parameters
            cmd = ["set", self.interface]
            
            # Add obfuscation parameters if provided and enabled
            if obfuscation and obfuscation.get('enabled', True):
                logger.info(f"Applying obfuscation parameters: {obfuscation}")
                if 'jc' in obfuscation and obfuscation['jc'] is not None:
                    cmd.extend(["jc", str(obfuscation['jc'])])
                if 'jmin' in obfuscation and obfuscation['jmin'] is not None:
                    cmd.extend(["jmin", str(obfuscation['jmin'])])
                if 'jmax' in obfuscation and obfuscation['jmax'] is not None:
                    cmd.extend(["jmax", str(obfuscation['jmax'])])
                if 's1' in obfuscation and obfuscation['s1'] is not None and obfuscation['s1'] > 0:
                    cmd.extend(["s1", str(obfuscation['s1'])])
                if 's2' in obfuscation and obfuscation['s2'] is not None and obfuscation['s2'] > 0:
                    cmd.extend(["s2", str(obfuscation['s2'])])
                if 's3' in obfuscation and obfuscation['s3'] is not None and obfuscation['s3'] > 0:
                    cmd.extend(["s3", str(obfuscation['s3'])])
                if 's4' in obfuscation and obfuscation['s4'] is not None and obfuscation['s4'] > 0:
                    cmd.extend(["s4", str(obfuscation['s4'])])
                if 'h1' in obfuscation and obfuscation['h1'] is not None:
                    cmd.extend(["h1", str(obfuscation['h1'])])
                if 'h2' in obfuscation and obfuscation['h2'] is not None:
                    cmd.extend(["h2", str(obfuscation['h2'])])
                if 'h3' in obfuscation and obfuscation['h3'] is not None:
                    cmd.extend(["h3", str(obfuscation['h3'])])
                if 'h4' in obfuscation and obfuscation['h4'] is not None:
                    cmd.extend(["h4", str(obfuscation['h4'])])
            
            # Add peer configuration
            cmd.extend([
                "peer", public_key,
                "allowed-ips", ",".join(allowed_ips),
                "persistent-keepalive", "25",
                "endpoint", f"0.0.0.0:{port}"  # Allow connections from any IP
            ])
            
            logger.info(f"AWG command: {' '.join(cmd)}")
            self.run_wg_command(cmd)
            
            # Update assigned IPs
            with self._ip_lock:
                if assigned_ipv4:
                    self.assigned_ipv4s.add(assigned_ipv4)
                if assigned_ipv6:
                    self.assigned_ipv6s.add(assigned_ipv6)
            
            logger.info(f"Added peer: {public_key} IPv4: {assigned_ipv4} IPv6: {assigned_ipv6}")
            return True, assigned_ipv4, assigned_ipv6
            
        except Exception as e:
            logger.error(f"Failed to add peer: {str(e)}")
            return False, None, None

    def remove_peer(self, public_key: str) -> bool:
        """Remove a peer with cleanup"""
        try:
            if not self.verify_peer_exists(public_key):
                return True

            # Get peer's IPs before removal
            result = self.run_wg_command(["show", self.interface])
            peer_ips = []
            for line in result.stdout.split('\n'):
                if public_key in line:
                    if "allowed ips:" in line.lower():
                        ips = line.split(':')[1].strip().split(',')
                        peer_ips = [ip.strip().split('/')[0] for ip in ips]

            # Remove peer
            cmd = ["set", self.interface, "peer", public_key, "remove"]
            self.run_wg_command(cmd)

            # Clean up IPs
            with self._ip_lock:
                for ip in peer_ips:
                    if ':' in ip:  # IPv6
                        self.assigned_ipv6s.discard(ip)
                    else:  # IPv4
                        self.assigned_ipv4s.discard(ip)

            logger.info(f"Removed peer: {public_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove peer: {e}")
            return False

    def sync_assigned_ips(self):
        """Sync assigned IPs with thread safety"""
        with self._ip_lock:
            try:
                # Clear current sets
                self.assigned_ipv4s.clear()
                self.assigned_ipv6s.clear()
                
                # Get IPs from WireGuard
                try:
                    result = self.run_wg_command(["show", self.interface])
                    for line in result.stdout.split('\n'):
                        if "allowed ips:" in line.lower():
                            ips = line.split(':')[1].strip().split(',')
                            for ip in ips:
                                ip = ip.strip().split('/')[0]
                                if ':' in ip:  # IPv6
                                    self.assigned_ipv6s.add(ip)
                                else:  # IPv4
                                    self.assigned_ipv4s.add(ip)
                except Exception as e:
                    logger.warning(f"Failed to get IPs from WireGuard: {e}")
                
                # Get IPs from database
                from database import SessionLocal
                db = SessionLocal()
                try:
                    from models import WGConfig
                    configs = db.query(WGConfig).all()
                    for config in configs:
                        if config.assigned_ip:
                            self.assigned_ipv4s.add(config.assigned_ip)
                        if config.assigned_ipv6:
                            self.assigned_ipv6s.add(config.assigned_ipv6)
                finally:
                    db.close()
                    
            except Exception as e:
                logger.error(f"Failed to sync IPs: {e}")
                raise

    def get_ip_usage(self) -> Dict:
        """Get thread-safe IP usage statistics"""
        with self._ip_lock:
            return {
                "ipv4": {
                    "total": MAX_PEERS,
                    "used": len(self.assigned_ipv4s),
                    "available": MAX_PEERS - len(self.assigned_ipv4s),
                    "assigned_ips": list(sorted(self.assigned_ipv4s)),
                    "gateway_ip": self.gateway_ipv4
                },
                "ipv6": {
                    "total": MAX_PEERS,
                    "used": len(self.assigned_ipv6s),
                    "available": MAX_PEERS - len(self.assigned_ipv6s),
                    "assigned_ips": list(sorted(self.assigned_ipv6s)),
                    "gateway_ip": self.gateway_ipv6
                }
            }

    def verify_peer_exists(self, public_key: str) -> bool:
        """Thread-safe peer verification"""
        try:
            result = self.run_wg_command(["show"])
            return public_key in result.stdout
        except:
            return False

    def get_active_peer_count(self) -> int:
        """Get thread-safe active peer count"""
        try:
            result = self.run_wg_command(["show", self.interface])
            active_count = 0
            for line in result.stdout.splitlines():
                if 'latest handshake:' in line:
                    handshake_time = line.split(':')[1].strip()
                    if handshake_time and 'never' not in handshake_time.lower():
                        active_count += 1
            return active_count
        except Exception as e:
            logger.error(f"Error getting active peer count: {str(e)}")
            return 0

    def get_total_peer_count(self) -> int:
        """Get thread-safe total peer count"""
        try:
            result = self.run_wg_command(["show", self.interface, "peers"])
            return len([p for p in result.stdout.splitlines() if p.strip()])
        except Exception as e:
            logger.error(f"Error getting total peer count: {str(e)}")
            return 0

    def sync_and_reconstruct_peers(self):
        """Thread-safe peer reconstruction"""
        try:
            # First get all current peers
            result = self.run_wg_command(["show", self.interface, "peers"])
            current_peers = [peer.strip() for peer in result.stdout.splitlines() if peer.strip()]
            
            # Remove each peer individually
            for peer in current_peers:
                try:
                    self.run_wg_command(["set", self.interface, "peer", peer, "remove"])
                    logger.info(f"Removed peer: {peer}")
                except Exception as e:
                    logger.warning(f"Failed to remove peer {peer}: {e}")
            
            # Clear assigned IPs
            with self._ip_lock:
                self.assigned_ipv4s.clear()
                self.assigned_ipv6s.clear()
            
            # Reconstruct from database
            from database import SessionLocal
            db = SessionLocal()
            try:
                from models import WGConfig
                active_configs = db.query(WGConfig).filter(WGConfig.status == 'active').all()
                
                # Process peers in batches
                for i in range(0, len(active_configs), BATCH_SIZE):
                    batch = active_configs[i:i + BATCH_SIZE]
                    for config in batch:
                        try:
                            # Ensure tunnel_traffic is valid
                            tunnel_traffic = config.tunnel_traffic
                            if not tunnel_traffic:
                                tunnel_traffic = ['ipv4']  # Default to IPv4
                                
                            success, ipv4, ipv6 = self.add_peer(
                                config.public_key,
                                protocol='dual' if config.assigned_ipv6 else None,
                                tunnel_traffic=tunnel_traffic,
                                port=config.assigned_port or 51820,  # Default to 51820 if port is None
                                assigned_ipv4=config.assigned_ip,
                                assigned_ipv6=config.assigned_ipv6
                            )
                            if success:
                                logger.info(f"Reconstructed peer: {config.public_key}")
                                with self._ip_lock:
                                    if ipv4:
                                        self.assigned_ipv4s.add(ipv4)
                                    if ipv6:
                                        self.assigned_ipv6s.add(ipv6)
                            else:
                                logger.warning(f"Failed to reconstruct peer: {config.public_key}")
                        except Exception as e:
                            logger.error(f"Error reconstructing peer {config.public_key}: {e}")
                    
                    # Small delay between batches to prevent overload
                    time.sleep(0.1)
            
            finally:
                db.close()
            
            logger.info(f"Reconstructed {len(self.assigned_ipv4s) + len(self.assigned_ipv6s)} active peers")
            
        except Exception as e:
            logger.error(f"Peer reconstruction failed: {e}")

    def get_allowed_ips(self, tunnel_traffic: List[str]) -> List[str]:
        """Get allowed IPs based on tunnel traffic configuration"""
        allowed_ips = []
        
        if 'ipv4' in tunnel_traffic:
            # Allow traffic to the entire IPv4 internet through the VPN
            allowed_ips.append("0.0.0.0/0")
        if 'ipv6' in tunnel_traffic:
            # Allow traffic to the entire IPv6 internet through the VPN
            allowed_ips.append("::/0")
            
        return allowed_ips

    def __del__(self):
        """Cleanup on shutdown"""
        try:
            COMMAND_QUEUE.put(None)  # Signal shutdown
            self.command_thread.join(timeout=5)
        except:
            pass

