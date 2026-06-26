import struct
from typing import Optional

class ParsedPacket:
    def __init__(self):
        self.timestamp_sec = 0
        self.timestamp_usec = 0
        self.src_mac = ""
        self.dest_mac = ""
        self.ether_type = 0
        
        self.has_ip = False
        self.ip_version = 0
        self.ttl = 0
        self.protocol = 0
        self.src_ip = ""
        self.dest_ip = ""
        
        self.has_tcp = False
        self.has_udp = False
        self.src_port = 0
        self.dest_port = 0
        self.seq_number = 0
        self.ack_number = 0
        self.tcp_flags = 0
        
        self.payload_length = 0
        self.payload_data = b""

class PacketParser:
    @staticmethod
    def parse(raw_data: bytes, ts_sec: int, ts_usec: int) -> Optional[ParsedPacket]:
        parsed = ParsedPacket()
        parsed.timestamp_sec = ts_sec
        parsed.timestamp_usec = ts_usec
        
        length = len(raw_data)
        if length < 14:
            return None
            
        # Parse Ethernet header
        parsed.dest_mac = ":".join(f"{b:02x}" for b in raw_data[0:6])
        parsed.src_mac = ":".join(f"{b:02x}" for b in raw_data[6:12])
        parsed.ether_type, = struct.unpack('>H', raw_data[12:14])
        
        offset = 14
        
        # Check if EtherType is IPv4 (0x0800)
        if parsed.ether_type == 0x0800:
            if length < offset + 20:
                return None
                
            ip_header = raw_data[offset:offset+20]
            version_ihl = ip_header[0]
            parsed.ip_version = (version_ihl >> 4) & 0x0F
            ihl = version_ihl & 0x0F
            
            if parsed.ip_version != 4:
                return None
                
            ip_header_len = ihl * 4
            if ip_header_len < 20 or length < offset + ip_header_len:
                return None
                
            parsed.ttl = ip_header[8]
            parsed.protocol = ip_header[9]
            
            # String IPs matching the index ordering of the network bytes
            parsed.src_ip = f"{ip_header[12]}.{ip_header[13]}.{ip_header[14]}.{ip_header[15]}"
            parsed.dest_ip = f"{ip_header[16]}.{ip_header[17]}.{ip_header[18]}.{ip_header[19]}"
            parsed.has_ip = True
            
            offset += ip_header_len
            
            # TCP Protocol (6)
            if parsed.protocol == 6:
                if length < offset + 20:
                    return None
                    
                tcp_header = raw_data[offset:offset+20]
                parsed.src_port, parsed.dest_port, parsed.seq_number, parsed.ack_number = \
                    struct.unpack('>HHII', tcp_header[0:12])
                    
                data_offset = (tcp_header[12] >> 4) & 0x0F
                tcp_header_len = data_offset * 4
                parsed.tcp_flags = tcp_header[13]
                
                if tcp_header_len < 20 or length < offset + tcp_header_len:
                    return None
                    
                parsed.has_tcp = True
                offset += tcp_header_len
                
            # UDP Protocol (17)
            elif parsed.protocol == 17:
                if length < offset + 8:
                    return None
                    
                udp_header = raw_data[offset:offset+8]
                parsed.src_port, parsed.dest_port = struct.unpack('>HH', udp_header[0:4])
                parsed.has_udp = True
                offset += 8
                
        # Set payload
        if offset < length:
            parsed.payload_length = length - offset
            parsed.payload_data = raw_data[offset:]
        else:
            parsed.payload_length = 0
            parsed.payload_data = b""
            
        return parsed

def protocolToString(protocol: int) -> str:
    if protocol == 1:
        return "ICMP"
    elif protocol == 6:
        return "TCP"
    elif protocol == 17:
        return "UDP"
    return f"Unknown({protocol})"

def tcpFlagsToString(flags: int) -> str:
    parts = []
    if flags & 0x02: parts.append("SYN")
    if flags & 0x10: parts.append("ACK")
    if flags & 0x01: parts.append("FIN")
    if flags & 0x04: parts.append("RST")
    if flags & 0x08: parts.append("PSH")
    if flags & 0x20: parts.append("URG")
    return " ".join(parts) if parts else "none"
