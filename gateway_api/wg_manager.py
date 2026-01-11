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

    def generate_ip_for_interface(self, interface: str, ip_type: str) -> Optional[str]:
        """Generate IP address for specific interface using its subnet"""
        import os
        import ipaddress
        from dotenv import dotenv_values
        
        # Load env from file
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        env_vars = dotenv_values(env_path)
        
        # Get subnet from env
        if ip_type == 'ipv4':
            env_key = f"INTERFACE_{interface}_IPV4_SUBNET"
            subnet_str = env_vars.get(env_key, "10.0.1.0/24")
        else:
            env_key = f"INTERFACE_{interface}_IPV6_SUBNET"
            subnet_str = env_vars.get(env_key, "fd42:4242:1::/64")
        
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            # Get existing peers to avoid conflicts
            existing_ips = set()
            try:
                result = subprocess.run(
                    ["sudo", "awg", "show", interface, "allowed-ips"],
                    capture_output=True, text=True
                )
                for line in result.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 2:
                        for ip_cidr in parts[1].split(","):
                            ip = ip_cidr.split("/")[0]
                            existing_ips.add(ip)
            except:
                pass
            
            # Find next available IP (skip .0, .1 - gateway address)
            for i, ip in enumerate(network.hosts()):
                if i == 0:  # Skip gateway address
                    continue
                if str(ip) not in existing_ips:
                    logger.info(f"Generated IP {ip} for interface {interface}")
                    return str(ip)
            
            raise Exception(f"No available IPs in {subnet_str}")
        except Exception as e:
            logger.error(f"Failed to generate IP for {interface}: {e}")
            # Fallback to default
            return self.generate_ip_addresses(ip_type)[0 if ip_type == 'ipv4' else 1]

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

    def add_peer(self, public_key, protocol=None, tunnel_traffic=['ipv4'], port=51820, assigned_ipv4=None, assigned_ipv6=None, obfuscation=None, obfuscation_level='off'):
        """Add a new peer with optimized IP assignment and AmneziaWG obfuscation"""
        try:
            # Map obfuscation_level to interface
            interface_map = {'off': 'wg0', 'basic': 'wg1', 'high': 'wg2', 'stealth': 'wg3'}
            target_interface = interface_map.get(obfuscation_level, 'wg0')
            logger.info(f"Obfuscation level '{obfuscation_level}' -> interface {target_interface}")
            
            # Ensure tunnel_traffic is not empty
            if not tunnel_traffic:
                tunnel_traffic = ['ipv4']  # Default to IPv4 if tunnel_traffic is empty
                
            # Determine which addresses to assign
            use_ipv4 = 'ipv4' in tunnel_traffic
            use_ipv6 = 'ipv6' in tunnel_traffic
            
            logger.info(f"Adding peer: {public_key} (protocol: {protocol}, tunnel: {tunnel_traffic}, obfuscation: {bool(obfuscation)})")
            
            # Generate IP addresses for target interface
            if assigned_ipv4 is None and use_ipv4:
                assigned_ipv4 = self.generate_ip_for_interface(target_interface, 'ipv4')
            if assigned_ipv6 is None and use_ipv6:
                assigned_ipv6 = self.generate_ip_for_interface(target_interface, 'ipv6')
            
            # Ensure at least one IP address is assigned
            if not assigned_ipv4 and not assigned_ipv6:
                assigned_ipv4 = self.generate_ip_for_interface(target_interface, 'ipv4')
                
            # Build allowed IPs
            allowed_ips = []
            if assigned_ipv4:
                allowed_ips.append(f"{assigned_ipv4}/32")
            if assigned_ipv6:
                allowed_ips.append(f"{assigned_ipv6}/128")
            
            if not allowed_ips:
                raise Exception("No valid IP addresses assigned")
            
            # Build AWG command with obfuscation parameters
            cmd = ["set", target_interface]
            
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
        """Remove a peer from all interfaces"""
        try:
            removed = False
            # Check all interfaces for this peer
            for interface in ['wg0', 'wg1', 'wg2', 'wg3']:
                try:
                    result = self.run_wg_command(["show", interface])
                    if public_key in result.stdout:
                        # Get peer's IPs before removal
                        peer_ips = []
                        for line in result.stdout.split('\n'):
                            if "allowed ips:" in line.lower():
                                ips = line.split(':')[1].strip().split(',')
                                peer_ips = [ip.strip().split('/')[0] for ip in ips if ip.strip()]
                        
                        # Remove peer from this interface
                        cmd = ["set", interface, "peer", public_key, "remove"]
                        self.run_wg_command(cmd)
                        logger.info(f"Removed peer {public_key} from {interface}")
                        removed = True
                        
                        # Clean up IPs
                        with self._ip_lock:
                            for ip in peer_ips:
                                if ':' in ip:  # IPv6
                                    self.assigned_ipv6s.discard(ip)
                                else:  # IPv4
                                    self.assigned_ipv4s.discard(ip)
                except Exception as e:
                    logger.debug(f"Interface {interface} check failed: {e}")
                    continue
            
            return removed
        except Exception as e:
            logger.error(f"Failed to remove peer: {e}")
            return False

    def sync_assigned_ips(self):
        """Sync assigned IPs from WireGuard state (RAM-only mode)"""
        with self._ip_lock:
            try:
                # Clear current sets
                self.assigned_ipv4s.clear()
                self.assigned_ipv6s.clear()
                
                # Get IPs from all WireGuard interfaces
                all_interfaces = ['wg0', 'wg1', 'wg2', 'wg3']
                for interface in all_interfaces:
                    try:
                        result = self.run_wg_command(["show", interface, "allowed-ips"])
                        for line in result.stdout.splitlines():
                            parts = line.strip().split('\t')
                            if len(parts) >= 2:
                                allowed_ips = parts[1].split(',')
                                for ip_cidr in allowed_ips:
                                    ip = ip_cidr.strip().split('/')[0]
                                    if ip:
                                        if ':' in ip:
                                            self.assigned_ipv6s.add(ip)
                                        else:
                                            self.assigned_ipv4s.add(ip)
                    except Exception as e:
                        logger.debug(f"Could not check interface {interface}: {e}")
                
                logger.info(f"IP sync: {len(self.assigned_ipv4s)} IPv4, {len(self.assigned_ipv6s)} IPv6")
                    
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

    def get_interface_from_ip(self, ip_address: str) -> str:
        """
        Derive the WireGuard interface from the assigned IP address.
        
        IP Ranges by Interface:
            wg0 (off):     10.5.30.x
            wg1 (basic):   10.5.31.x
            wg2 (high):    10.5.32.x
            wg3 (stealth): 10.5.33.x
        
        Returns the interface name (wg0, wg1, wg2, wg3) or 'wg0' as default.
        """
        if not ip_address:
            return 'wg0'
        
        try:
            # Extract the third octet from the IP
            parts = ip_address.split('.')
            if len(parts) >= 3:
                third_octet = int(parts[2])
                interface_map = {
                    30: 'wg0',  # off
                    31: 'wg1',  # basic
                    32: 'wg2',  # high
                    33: 'wg3',  # stealth
                }
                return interface_map.get(third_octet, 'wg0')
        except (ValueError, IndexError) as e:
            logger.warning(f"Could not derive interface from IP {ip_address}: {e}")
        
        return 'wg0'  # Default fallback

    def get_obfuscation_level_from_ip(self, ip_address: str) -> str:
        """
        Derive the obfuscation level from the assigned IP address.
        
        IP Ranges to Obfuscation Level:
            10.5.30.x -> 'off'
            10.5.31.x -> 'basic'
            10.5.32.x -> 'high'
            10.5.33.x -> 'stealth'
        """
        interface = self.get_interface_from_ip(ip_address)
        level_map = {
            'wg0': 'off',
            'wg1': 'basic',
            'wg2': 'high',
            'wg3': 'stealth'
        }
        return level_map.get(interface, 'off')

    def sync_assigned_ips_from_wireguard(self):
        """
        Sync assigned IP tracking from current WireGuard state.
        
        This is used in RAM-only mode to ensure IP tracking is accurate
        without wiping peers. Just reads current peers and tracks their IPs.
        """
        try:
            all_interfaces = ['wg0', 'wg1', 'wg2', 'wg3']
            
            with self._ip_lock:
                self.assigned_ipv4s.clear()
                self.assigned_ipv6s.clear()
            
            for interface in all_interfaces:
                try:
                    result = self.run_wg_command(["show", interface, "allowed-ips"])
                    for line in result.stdout.splitlines():
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            allowed_ips = parts[1].split(',')
                            for ip_cidr in allowed_ips:
                                ip = ip_cidr.strip().split('/')[0]
                                if ip:
                                    if ':' in ip:
                                        self.assigned_ipv6s.add(ip)
                                    else:
                                        self.assigned_ipv4s.add(ip)
                except Exception as e:
                    logger.debug(f"Could not check interface {interface}: {e}")
            
            logger.info(f"IP sync complete: {len(self.assigned_ipv4s)} IPv4, {len(self.assigned_ipv6s)} IPv6 tracked")
            
        except Exception as e:
            logger.error(f"Failed to sync IPs from WireGuard: {e}")

    def sync_and_reconstruct_peers(self):
        """
        DEPRECATED: This function was used for SQLite-based peer reconstruction.
        
        In RAM-only mode, peer reconstruction is handled by:
        1. main.py startup_event() - recovers peers from mesh
        2. sync_assigned_ips_from_wireguard() - syncs IP tracking
        
        This function is kept for backwards compatibility but does nothing.
        """
        logger.warning("sync_and_reconstruct_peers() is deprecated in RAM-only mode - use mesh recovery instead")

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

