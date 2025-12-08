# gateway_api/models.py
from sqlalchemy import Column, String, Integer, DateTime, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, UTC

Base = declarative_base()

class WGConfig(Base):
    __tablename__ = "wg_configs"

    public_key = Column(String, primary_key=True, index=True)
    
    # IP Configuration
    assigned_ip = Column(String)        # IPv4 address
    assigned_ipv6 = Column(String)      # IPv6 address
    assigned_port = Column(Integer, default=51820)
    
    # Traffic Configuration
    tunnel_traffic = Column(JSON, default=lambda: ['ipv4'])  # ['ipv4'], ['ipv6'], or ['ipv4', 'ipv6']
    dns_choice = Column(String, default='d1')  # 'd1', 'd2', 'd3'
    allowed_ips = Column(String)  # Computed based on tunnel_traffic
    
    # Status and Metadata
    status = Column(String)  # active/suspended
    last_handshake = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    is_online = Column(Boolean, default=False)
    
    # AmneziaWG Obfuscation Parameters
    obfuscation_enabled = Column(Boolean, default=True)
    junk_packet_count = Column(Integer, default=3)           # jc: Number of junk packets (0-128)
    junk_packet_min_size = Column(Integer, default=50)       # jmin: Min junk size (0-1280)
    junk_packet_max_size = Column(Integer, default=1000)     # jmax: Max junk size (0-1280)
    init_packet_junk_size = Column(Integer, default=0)       # s1: Init handshake junk size
    response_packet_junk_size = Column(Integer, default=0)   # s2: Response handshake junk size
    underload_packet_junk_size = Column(Integer, default=0)  # s3: Under load junk size
    transport_packet_junk_size = Column(Integer, default=0)  # s4: Transport data junk size
    init_packet_magic_header = Column(Integer, default=1)    # h1: Init packet magic header
    response_packet_magic_header = Column(Integer, default=2)  # h2: Response packet magic header
    underload_packet_magic_header = Column(Integer, default=3) # h3: Under load packet magic header
    transport_packet_magic_header = Column(Integer, default=4) # h4: Transport packet magic header

    def __repr__(self):
        return f"<WGConfig(public_key={self.public_key}, ipv4={self.assigned_ip}, ipv6={self.assigned_ipv6}, obfuscation={self.obfuscation_enabled})>"
