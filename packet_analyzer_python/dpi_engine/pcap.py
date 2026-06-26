import struct
from typing import Optional, Dict, Any

class PcapReader:
    def __init__(self, filename: str):
        self.filename = filename
        self.file = None
        self.endian = '<'
        self.version_major = 0
        self.version_minor = 0
        self.snaplen = 0
        self.network = 0
        self.global_header_bytes = b''

    def open(self) -> bool:
        try:
            self.file = open(self.filename, 'rb')
            magic_bytes = self.file.read(4)
            if len(magic_bytes) < 4:
                print("Error: Could not read PCAP magic number (file too short)")
                return False
                
            magic_le, = struct.unpack('<I', magic_bytes)
            if magic_le == 0xa1b2c3d4:
                self.endian = '<'
            elif magic_le == 0xd4c3b2a1:
                self.endian = '>'
            else:
                magic_be, = struct.unpack('>I', magic_bytes)
                if magic_be == 0xa1b2c3d4:
                    self.endian = '>'
                else:
                    print(f"Error: Invalid PCAP magic number: 0x{magic_bytes.hex()}")
                    return False
                    
            rest_header = self.file.read(20)
            if len(rest_header) < 20:
                print("Error: Could not read PCAP global header")
                self.close()
                return False
                
            self.global_header_bytes = magic_bytes + rest_header
            
            _, self.version_major, self.version_minor, self.thiszone, self.sigfigs, self.snaplen, self.network = \
                struct.unpack(f'{self.endian}IHHIIII', self.global_header_bytes)
                
            print(f"Opened PCAP file: {self.filename}")
            print(f"  Version: {self.version_major}.{self.version_minor}")
            print(f"  Snaplen: {self.snaplen} bytes")
            print(f"  Link type: {self.network}{' (Ethernet)' if self.network == 1 else ''}")
            return True
        except Exception as e:
            print(f"Error: Could not open file: {self.filename} ({e})")
            return False
            
    def read_next_packet(self) -> Optional[Dict[str, Any]]:
        if not self.file:
            return None
            
        hdr_bytes = self.file.read(16)
        if len(hdr_bytes) < 16:
            return None  # End of file or partial read
            
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{self.endian}IIII', hdr_bytes)
        
        # Sanity check on packet length matching the C++ reader
        if incl_len > self.snaplen or incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}")
            return None
            
        data_bytes = self.file.read(incl_len)
        if len(data_bytes) < incl_len:
            print("Error: Could not read packet data")
            return None
            
        return {
            'ts_sec': ts_sec,
            'ts_usec': ts_usec,
            'incl_len': incl_len,
            'orig_len': orig_len,
            'data': data_bytes
        }

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

class PcapWriter:
    def __init__(self, filename: str, global_header: Optional[bytes] = None, endian: str = '<',
                 version_major: int = 2, version_minor: int = 4, snaplen: int = 65535, network: int = 1):
        self.filename = filename
        self.file = None
        self.global_header = global_header
        self.endian = endian
        self.version_major = version_major
        self.version_minor = version_minor
        self.snaplen = snaplen
        self.network = network

    def open(self) -> bool:
        try:
            self.file = open(self.filename, 'wb')
            if self.global_header:
                self.file.write(self.global_header)
            else:
                header = struct.pack(
                    f'{self.endian}IHHIIII',
                    0xa1b2c3d4,
                    self.version_major,
                    self.version_minor,
                    0, 0,
                    self.snaplen,
                    self.network
                )
                self.file.write(header)
            return True
        except Exception as e:
            print(f"Error: Cannot open output file {self.filename} ({e})")
            return False

    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes):
        if not self.file:
            return
        incl_len = len(data)
        orig_len = incl_len
        hdr_bytes = struct.pack(f'{self.endian}IIII', ts_sec, ts_usec, incl_len, orig_len)
        self.file.write(hdr_bytes)
        self.file.write(data)

    def close(self):
        if self.file:
            self.file.close()
            self.file = None
