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

    def __repr__(self):
        return f"<WGConfig(public_key={self.public_key}, ipv4={self.assigned_ip}, ipv6={self.assigned_ipv6})>"
