import struct
from typing import Optional, List, Tuple

class SNIExtractor:
    @staticmethod
    def read_uint16_be(data: bytes, offset: int) -> int:
        return (data[offset] << 8) | data[offset+1]

    @staticmethod
    def read_uint24_be(data: bytes, offset: int) -> int:
        return (data[offset] << 16) | (data[offset+1] << 8) | data[offset+2]

    @classmethod
    def is_tls_client_hello(cls, payload: bytes, length: int) -> bool:
        if length < 9:
            return False
            
        # Byte 0: Content Type (should be 0x16 = Handshake)
        if payload[0] != 0x16:
            return False
            
        # Bytes 1-2: TLS Version (SSL 3.0 to TLS 1.3, i.e. 0x0300 to 0x0304)
        version = cls.read_uint16_be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False
            
        # Bytes 3-4: Record length
        record_length = cls.read_uint16_be(payload, 3)
        if record_length > length - 5:
            return False
            
        # Byte 5: Handshake Type (should be 0x01 = Client Hello)
        if payload[5] != 0x01:
            return False
            
        return True

    @classmethod
    def extract(cls, payload: bytes, length: int) -> Optional[str]:
        if not cls.is_tls_client_hello(payload, length):
            return None
            
        # Skip TLS record header (5 bytes)
        offset = 5
        
        # Skip handshake header
        # Byte 0: Handshake type (1 byte, already checked)
        # Bytes 1-3: Length (3 bytes)
        offset += 4
        
        # Client Hello body
        # Bytes 0-1: Client version
        offset += 2
        
        # Bytes 2-33: Random (32 bytes)
        offset += 32
        
        # Session ID
        if offset >= length:
            return None
        session_id_length = payload[offset]
        offset += 1 + session_id_length
        
        # Cipher suites
        if offset + 2 > length:
            return None
        cipher_suites_length = cls.read_uint16_be(payload, offset)
        offset += 2 + cipher_suites_length
        
        # Compression methods
        if offset >= length:
            return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length
        
        # Extensions
        if offset + 2 > length:
            return None
        extensions_length = cls.read_uint16_be(payload, offset)
        offset += 2
        
        extensions_end = offset + extensions_length
        if extensions_end > length:
            extensions_end = length
            
        # Parse extensions to find SNI (0x0000)
        while offset + 4 <= extensions_end:
            extension_type = cls.read_uint16_be(payload, offset)
            extension_length = cls.read_uint16_be(payload, offset + 2)
            offset += 4
            
            if offset + extension_length > extensions_end:
                break
                
            if extension_type == 0x0000:
                # SNI extension found
                if extension_length < 5:
                    break
                    
                sni_list_length = cls.read_uint16_be(payload, offset)
                if sni_list_length < 3:
                    break
                    
                sni_type = payload[offset + 2]
                sni_length = cls.read_uint16_be(payload, offset + 3)
                
                if sni_type != 0x00:  # Hostname type
                    break
                if sni_length > extension_length - 5:
                    break
                    
                # Extract host
                try:
                    sni = payload[offset + 5: offset + 5 + sni_length].decode('ascii', errors='ignore')
                    return sni
                except Exception:
                    break
                    
            offset += extension_length
            
        return None

class HTTPHostExtractor:
    @staticmethod
    def is_http_request(payload: bytes, length: int) -> bool:
        if length < 4:
            return False
            
        # Common HTTP methods
        methods = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]
        prefix = payload[0:4]
        return any(prefix == m for m in methods)

    @classmethod
    def extract(cls, payload: bytes, length: int) -> Optional[str]:
        if not cls.is_http_request(payload, length):
            return None
            
        # Search for Host: header
        lower_payload = payload.lower()
        idx = lower_payload.find(b"host:")
        if idx != -1:
            start = idx + 5
            # Skip spaces/tabs
            while start < length and (payload[start] == 32 or payload[start] == 9):  # space or tab
                start += 1
                
            end = start
            while end < length and payload[end] not in (13, 10):  # CR or LF
                end += 1
                
            if end > start:
                try:
                    host = payload[start:end].decode('ascii', errors='ignore')
                    # Strip port if present
                    if ':' in host:
                        host = host.split(':')[0]
                    return host
                except Exception:
                    pass
        return None

class DNSExtractor:
    @staticmethod
    def is_dns_query(payload: bytes, length: int) -> bool:
        if length < 12:
            return False
            
        # Check QR bit (byte 2, bit 7) - must be 0 for queries
        flags = payload[2]
        if flags & 0x80:
            return False
            
        # Check QDCOUNT (bytes 4-5) - must be > 0
        qdcount = (payload[4] << 8) | payload[5]
        if qdcount == 0:
            return False
            
        return True

    @classmethod
    def extract_query(cls, payload: bytes, length: int) -> Optional[str]:
        if not cls.is_dns_query(payload, length):
            return None
            
        offset = 12
        labels: List[str] = []
        
        while offset < length:
            label_length = payload[offset]
            if label_length == 0:
                break
            if label_length > 63:
                break  # Compression or invalid
                
            offset += 1
            if offset + label_length > length:
                break
                
            try:
                label = payload[offset: offset + label_length].decode('ascii', errors='ignore')
                labels.append(label)
            except Exception:
                break
                
            offset += label_length
            
        return ".".join(labels) if labels else None

class QUICSNIExtractor:
    @staticmethod
    def is_quic_initial(payload: bytes, length: int) -> bool:
        if length < 5:
            return False
        # QUIC long header form (first bit set)
        return bool(payload[0] & 0x80)

    @classmethod
    def extract(cls, payload: bytes, length: int) -> Optional[str]:
        if not cls.is_quic_initial(payload, length):
            return None
            
        # Slide search window looking for Client Hello signature (handshake type 0x01)
        for i in range(5, length - 50):
            if payload[i] == 0x01:  # Client Hello handshake type
                # Attempt SNI extraction on payload offset i-5
                result = SNIExtractor.extract(payload[i-5:], length - i + 5)
                if result:
                    return result
        return None
