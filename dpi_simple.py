#!/usr/bin/env python3
import sys
from packet_analyzer_python.dpi_engine.pcap import PcapReader, PcapWriter
from packet_analyzer_python.dpi_engine.parser import PacketParser, protocolToString
from packet_analyzer_python.dpi_engine.sni import SNIExtractor, HTTPHostExtractor
from packet_analyzer_python.dpi_engine.types import FiveTuple, Flow, AppType, appTypeToString, sniToAppType
from packet_analyzer_python.dpi_engine.rules import BlockingRules, parse_ip

def print_usage(prog_name):
    print(f"""
DPI Engine - Deep Packet Inspection System (Python Simple)
=========================================================

Usage: {prog_name} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  {prog_name} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")

def main():
    import io
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')
        
    if len(sys.argv) < 3:
        print_usage(sys.argv[0])
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    rules = BlockingRules()
    
    # Parse options
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            i += 1
            rules.block_ip(sys.argv[i])
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            i += 1
            rules.block_app(sys.argv[i])
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            i += 1
            rules.block_domain(sys.argv[i])
        i += 1
        
    print("\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                    DPI ENGINE v1.0 (Python)                  ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")
    
    reader = PcapReader(input_file)
    if not reader.open():
        sys.exit(1)
        
    writer = PcapWriter(output_file, global_header=reader.global_header_bytes)
    if not writer.open():
        reader.close()
        sys.exit(1)
        
    flows = {}
    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats = {}
    
    print("[DPI] Processing packets...")
    
    while True:
        raw = reader.read_next_packet()
        if not raw:
            break
            
        total_packets += 1
        
        parsed = PacketParser.parse(raw['data'], raw['ts_sec'], raw['ts_usec'])
        if not parsed:
            continue
            
        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue
            
        # Create five-tuple
        tuple_key = FiveTuple(
            src_ip=parse_ip(parsed.src_ip),
            dst_ip=parse_ip(parsed.dest_ip),
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol
        )
        
        flow = flows.get(tuple_key)
        if not flow:
            flow = Flow(tuple=tuple_key)
            flows[tuple_key] = flow
            
        flow.packets += 1
        flow.bytes += len(raw['data'])
        
        # Try SNI extraction (TLS Client Hello)
        if (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTPS) and \
           not flow.sni and parsed.has_tcp and parsed.dest_port == 443:
            
            if parsed.payload_length > 5:
                sni = SNIExtractor.extract(parsed.payload_data, parsed.payload_length)
                if sni:
                    flow.sni = sni
                    flow.app_type = sniToAppType(sni)
                    flow.classified = True
                    
        # HTTP Host extraction
        if (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTP) and \
           not flow.sni and parsed.has_tcp and parsed.dest_port == 80:
           
            if parsed.payload_length > 10:
                host = HTTPHostExtractor.extract(parsed.payload_data, parsed.payload_length)
                if host:
                    flow.sni = host
                    flow.app_type = sniToAppType(host)
                    flow.classified = True
                    
        # DNS classification
        if flow.app_type == AppType.UNKNOWN and (parsed.dest_port == 53 or parsed.src_port == 53):
            flow.app_type = AppType.DNS
            flow.classified = True
            
        # Port-based fallback
        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP
                
        # Check rules
        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_key.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                sni_part = f": {flow.sni}" if flow.sni else ""
                print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({appTypeToString(flow.app_type)}{sni_part})")
                
        # Update app stats
        app_stats[flow.app_type] = app_stats.get(flow.app_type, 0) + 1
        
        # Forward or drop
        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            writer.write_packet(raw['ts_sec'], raw['ts_usec'], raw['data'])
            
    reader.close()
    writer.close()
    
    # Print report
    print("\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {total_packets:<10}                             ║")
    print(f"║ Forwarded:          {forwarded:<10}                             ║")
    print(f"║ Dropped:            {dropped:<10}                             ║")
    print(f"║ Active Flows:       {len(flows):<10}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                    APPLICATION BREAKDOWN                     ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    
    # Sort apps by packet count descending
    sorted_apps = sorted(app_stats.items(), key=lambda x: x[1], reverse=True)
    for app, count in sorted_apps:
        pct = 100.0 * count / total_packets if total_packets > 0 else 0.0
        bar_len = int(pct / 5)
        bar = "#" * bar_len
        app_str = appTypeToString(app)
        
        # We need to construct a line matching the C++ layout:
        # ║ HTTPS                39  50.6% ##########                     ║
        left_part = f"║ {app_str:<15} {count:>8} {pct:>5.1f}% {bar:<20}"
        # Pad right side to ensure the line width matches C++ exactly
        print(f"{left_part:<62}║")
        
    print("╚══════════════════════════════════════════════════════════════╝")
    
    # List unique SNIs
    print("\n[Detected Applications/Domains]")
    unique_snis = {}
    for flow in flows.values():
        if flow.sni:
            unique_snis[flow.sni] = flow.app_type
            
    for sni, app in sorted(unique_snis.items()):
        print(f"  - {sni} -> {appTypeToString(app)}")
        
    print(f"\nOutput written to: {output_file}\n")

if __name__ == '__main__':
    main()
