import threading
from typing import Set, List
from .types import AppType

def parse_ip(ip: str) -> int:
    result = 0
    octet = 0
    shift = 0
    for c in ip:
        if c == '.':
            result |= (octet << shift)
            shift += 8
            octet = 0
        elif '0' <= c <= '9':
            octet = octet * 10 + int(c)
    return result | (octet << shift)

class BlockingRules:
    def __init__(self):
        self.blocked_ips: Set[int] = set()
        self.blocked_apps: Set[AppType] = set()
        self.blocked_domains: List[str] = []
        self._lock = threading.Lock()

    def block_ip(self, ip: str):
        addr = parse_ip(ip)
        with self._lock:
            self.blocked_ips.add(addr)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app_name: str):
        from .types import appTypeToString
        found = False
        with self._lock:
            for i in range(AppType.app_count()):
                app = AppType(i)
                if appTypeToString(app) == app_name:
                    self.blocked_apps.add(app)
                    print(f"[Rules] Blocked app: {app_name}")
                    found = True
                    break
        if not found:
            print(f"[Rules] Unknown app: {app_name}")

    def block_domain(self, domain: str):
        with self._lock:
            self.blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app_type: AppType, sni: str) -> bool:
        with self._lock:
            if src_ip in self.blocked_ips:
                return True
            if app_type in self.blocked_apps:
                return True
            for dom in self.blocked_domains:
                if dom in sni:
                    return True
        return False
