from enum import Enum, auto
from dataclasses import dataclass, field
import threading
from typing import Dict, Set, Optional

class AppType(Enum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    # Specific applications
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    
    @classmethod
    def app_count(cls) -> int:
        return len(cls)

def appTypeToString(app_type: AppType) -> str:
    mapping = {
        AppType.UNKNOWN: "Unknown",
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.TLS: "TLS",
        AppType.QUIC: "QUIC",
        AppType.GOOGLE: "Google",
        AppType.FACEBOOK: "Facebook",
        AppType.YOUTUBE: "YouTube",
        AppType.TWITTER: "Twitter/X",
        AppType.INSTAGRAM: "Instagram",
        AppType.NETFLIX: "Netflix",
        AppType.AMAZON: "Amazon",
        AppType.MICROSOFT: "Microsoft",
        AppType.APPLE: "Apple",
        AppType.WHATSAPP: "WhatsApp",
        AppType.TELEGRAM: "Telegram",
        AppType.TIKTOK: "TikTok",
        AppType.SPOTIFY: "Spotify",
        AppType.ZOOM: "Zoom",
        AppType.DISCORD: "Discord",
        AppType.GITHUB: "GitHub",
        AppType.CLOUDFLARE: "Cloudflare"
    }
    return mapping.get(app_type, "Unknown")

def sniToAppType(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN
    
    lower_sni = sni.lower()
    
    # Check for known patterns
    # Google
    if any(p in lower_sni for p in ["google", "gstatic", "googleapis", "ggpht", "gvt1"]):
        # But check YouTube first if it contains google, or check youtube explicitly
        if any(yp in lower_sni for yp in ["youtube", "ytimg", "youtu.be", "yt3.ggpht"]):
            return AppType.YOUTUBE
        return AppType.GOOGLE
        
    # YouTube
    if any(p in lower_sni for p in ["youtube", "ytimg", "youtu.be", "yt3.ggpht"]):
        return AppType.YOUTUBE
        
    # Facebook
    if any(p in lower_sni for p in ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"]):
        return AppType.FACEBOOK
        
    # Instagram
    if any(p in lower_sni for p in ["instagram", "cdninstagram"]):
        return AppType.INSTAGRAM
        
    # WhatsApp
    if any(p in lower_sni for p in ["whatsapp", "wa.me"]):
        return AppType.WHATSAPP
        
    # Twitter/X
    if any(p in lower_sni for p in ["twitter", "twimg", "x.com", "t.co"]):
        return AppType.TWITTER
        
    # Netflix
    if any(p in lower_sni for p in ["netflix", "nflxvideo", "nflximg"]):
        return AppType.NETFLIX
        
    # Amazon
    if any(p in lower_sni for p in ["amazon", "amazonaws", "cloudfront", "aws"]):
        return AppType.AMAZON
        
    # Microsoft
    if any(p in lower_sni for p in ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"]):
        return AppType.MICROSOFT
        
    # Apple
    if any(p in lower_sni for p in ["apple", "icloud", "mzstatic", "itunes"]):
        return AppType.APPLE
        
    # Telegram
    if any(p in lower_sni for p in ["telegram", "t.me"]):
        return AppType.TELEGRAM
        
    # TikTok
    if any(p in lower_sni for p in ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]):
        return AppType.TIKTOK
        
    # Spotify
    if any(p in lower_sni for p in ["spotify", "scdn.co"]):
        return AppType.SPOTIFY
        
    # Zoom
    if "zoom" in lower_sni:
        return AppType.ZOOM
        
    # Discord
    if any(p in lower_sni for p in ["discord", "discordapp"]):
        return AppType.DISCORD
        
    # GitHub
    if any(p in lower_sni for p in ["github", "githubusercontent"]):
        return AppType.GITHUB
        
    # Cloudflare
    if any(p in lower_sni for p in ["cloudflare", "cf-"]):
        return AppType.CLOUDFLARE
        
    return AppType.HTTPS

@dataclass(frozen=True)
class FiveTuple:
    src_ip: int  # IPv4 in integer form
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP
    
    def reverse(self) -> 'FiveTuple':
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )
        
    def __str__(self) -> str:
        def format_ip(ip_int: int) -> str:
            return f"{(ip_int >> 0) & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
            
        proto_str = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else f"Proto:{self.protocol}"
        return f"{format_ip(self.src_ip)}:{self.src_port} -> {format_ip(self.dst_ip)}:{self.dst_port} ({proto_str})"

@dataclass
class Flow:
    tuple: Optional[FiveTuple] = None
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False

class Stats:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded = 0
        self.dropped = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        
        self.app_counts: Dict[AppType, int] = {}
        self.detected_snis: Dict[str, AppType] = {}
        self._lock = threading.Lock()
        
    def record_app(self, app: AppType, sni: str):
        with self._lock:
            self.app_counts[app] = self.app_counts.get(app, 0) + 1
            if sni:
                self.detected_snis[sni] = app

    def add_packet(self, byte_len: int, is_tcp: bool, is_udp: bool):
        with self._lock:
            self.total_packets += 1
            self.total_bytes += byte_len
            if is_tcp:
                self.tcp_packets += 1
            elif is_udp:
                self.udp_packets += 1

    def add_forwarded(self):
        with self._lock:
            self.forwarded += 1

    def add_dropped(self):
        with self._lock:
            self.dropped += 1
