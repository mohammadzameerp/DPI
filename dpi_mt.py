#!/usr/bin/env python3
import sys
import time
import queue
import threading
from typing import List, Dict, Optional, Any

from packet_analyzer_python.dpi_engine.pcap import PcapReader, PcapWriter
from packet_analyzer_python.dpi_engine.parser import PacketParser, protocolToString
from packet_analyzer_python.dpi_engine.sni import SNIExtractor, HTTPHostExtractor
from packet_analyzer_python.dpi_engine.types import FiveTuple, Flow, AppType, appTypeToString, sniToAppType, Stats
from packet_analyzer_python.dpi_engine.rules import BlockingRules, parse_ip

# =============================================================================
# Thread-Safe Queue Wrapper
# =============================================================================
class TSQueue:
    def __init__(self, max_size=10000):
        self.queue = queue.Queue(maxsize=max_size)
        self.is_shutdown = False

    def push(self, item):
        if self.is_shutdown:
            return
        try:
            self.queue.put(item, block=True, timeout=1.0)
        except queue.Full:
            pass

    def pop(self, timeout_ms=100) -> Optional[Any]:
        try:
            return self.queue.get(block=True, timeout=timeout_ms / 1000.0)
        except queue.Empty:
            return None

    def shutdown(self):
        self.is_shutdown = True


# =============================================================================
# Fast Path Processor (Worker Thread)
# =============================================================================
class FastPath:
    def __init__(self, fp_id: int, rules: BlockingRules, stats: Stats, output_queue: TSQueue):
        self.id = fp_id
        self.rules = rules
        self.stats = stats
        self.output_queue = output_queue
        self.input_queue = TSQueue()
        self.flows: Dict[FiveTuple, Flow] = {}
        self.running = False
        self.thread = None
        self.processed_count = 0

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.run, name=f"FP{self.id}")
        self.thread.start()

    def stop(self):
        self.running = False
        self.input_queue.shutdown()
        if self.thread and self.thread.is_alive():
            self.thread.join()

    def run(self):
        while self.running:
            pkt = self.input_queue.pop(100)
            if pkt is None:
                continue

            self.processed_count += 1
            tuple_key = pkt['tuple']
            data = pkt['data']
            
            # Get or create flow
            flow = self.flows.get(tuple_key)
            if not flow:
                flow = Flow(tuple=tuple_key)
                self.flows[tuple_key] = flow

            flow.packets += 1
            flow.bytes += len(data)

            # Try to classify
            if not flow.classified:
                self.classify_flow(pkt, flow)

            # Check blocking
            if not flow.blocked:
                flow.blocked = self.rules.is_blocked(tuple_key.src_ip, flow.app_type, flow.sni)

            # Record stats
            self.stats.record_app(flow.app_type, flow.sni)

            # Forward or drop
            if flow.blocked:
                self.stats.add_dropped()
            else:
                self.stats.add_forwarded()
                self.output_queue.push(pkt)

    def classify_flow(self, pkt, flow: Flow):
        payload_offset = pkt['payload_offset']
        payload_len = pkt['payload_length']
        data = pkt['data']

        has_payload = (payload_len > 0 and payload_offset < len(data))
        payload = data[payload_offset:] if has_payload else b""

        # TLS Client Hello SNI Extraction (port 443)
        if pkt['tuple'].dst_port == 443 and has_payload and payload_len > 5:
            sni = SNIExtractor.extract(payload, payload_len)
            if sni:
                flow.sni = sni
                flow.app_type = sniToAppType(sni)
                flow.classified = True
                return

        # HTTP Host Header Extraction (port 80)
        if pkt['tuple'].dst_port == 80 and has_payload and payload_len > 10:
            host = HTTPHostExtractor.extract(payload, payload_len)
            if host:
                flow.sni = host
                flow.app_type = sniToAppType(host)
                flow.classified = True
                return

        # DNS Classification (port 53)
        if pkt['tuple'].dst_port == 53 or pkt['tuple'].src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

        # Fallback port-based classification (doesn't classify so SNI check runs on subsequent data packets)
        if pkt['tuple'].dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif pkt['tuple'].dst_port == 80:
            flow.app_type = AppType.HTTP

# =============================================================================
# Load Balancer
# =============================================================================
class LoadBalancer:
    def __init__(self, lb_id: int, fps: List[FastPath]):
        self.id = lb_id
        self.fps = fps
        self.num_fps = len(fps)
        self.input_queue = TSQueue()
        self.running = False
        self.thread = None
        self.dispatched_count = 0

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.run, name=f"LB{self.id}")
        self.thread.start()

    def stop(self):
        self.running = False
        self.input_queue.shutdown()
        if self.thread and self.thread.is_alive():
            self.thread.join()

    def run(self):
        while self.running:
            pkt = self.input_queue.pop(100)
            if pkt is None:
                continue

            # Hash the five tuple to select a Fast Path worker consistently
            tuple_key = pkt['tuple']
            # Compute stable hash from FiveTuple fields
            h = hash(tuple_key)
            fp_idx = abs(h) % self.num_fps
            
            self.fps[fp_idx].input_queue.push(pkt)
            self.dispatched_count += 1

# =============================================================================
# Output Writer Thread Function
# =============================================================================
def output_writer_run(output_queue: TSQueue, writer: PcapWriter, state: dict):
    while state['running'] or output_queue.queue.qsize() > 0:
        pkt = output_queue.pop(100)
        if pkt is None:
            continue
        writer.write_packet(pkt['ts_sec'], pkt['ts_usec'], pkt['data'])

# =============================================================================
# CLI Main Orchestrator
# =============================================================================
def print_usage(prog_name):
    print(f"""
DPI Engine - Deep Packet Inspection System (Python Multi-threaded)
==================================================================

Usage: {prog_name} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --lbs <num>            Number of Load Balancer threads (default: 2)
  --fps <num>            Number of Fast Path threads per LB (default: 2)

Example:
  {prog_name} capture.pcap filtered.pcap --block-app YouTube --lbs 4 --fps 4
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
    num_lbs = 2
    fps_per_lb = 2

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
        elif arg == "--lbs" and i + 1 < len(sys.argv):
            i += 1
            num_lbs = int(sys.argv[i])
        elif arg == "--fps" and i + 1 < len(sys.argv):
            i += 1
            fps_per_lb = int(sys.argv[i])
        i += 1

    total_fps = num_lbs * fps_per_lb

    print("\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║              DPI ENGINE v2.0 (Python Multi-threaded)         ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Load Balancers: {num_lbs:<2}    FPs per LB: {fps_per_lb:<2}    Total FPs: {total_fps:<2}     ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    reader = PcapReader(input_file)
    if not reader.open():
        sys.exit(1)

    writer = PcapWriter(output_file, global_header=reader.global_header_bytes)
    if not writer.open():
        reader.close()
        sys.exit(1)

    stats = Stats()
    output_queue = TSQueue()

    # Initialize FP threads
    fps: List[FastPath] = []
    for fp_id in range(total_fps):
        fp = FastPath(fp_id, rules, stats, output_queue)
        fps.append(fp)
        fp.start()

    # Initialize LB threads
    lbs: List[LoadBalancer] = []
    for lb_id in range(num_lbs):
        lb_fps = fps[lb_id * fps_per_lb : (lb_id + 1) * fps_per_lb]
        lb = LoadBalancer(lb_id, lb_fps)
        lbs.append(lb)
        lb.start()

    # Start Output Writer Thread
    writer_state = {'running': True}
    writer_thread = threading.Thread(
        target=output_writer_run, 
        args=(output_queue, writer, writer_state), 
        name="OutputWriter"
    )
    writer_thread.start()

    print("[Reader] Processing packets...")

    # Read packets sequentially in the main thread (Reader Thread)
    while True:
        raw = reader.read_next_packet()
        if not raw:
            break

        stats.add_packet(
            byte_len=len(raw['data']), 
            is_tcp=(b'TCP' in raw), # wait, TCP will be determined by parsing below
            is_udp=False # will be set properly below
        )

        parsed = PacketParser.parse(raw['data'], raw['ts_sec'], raw['ts_usec'])
        if not parsed:
            continue

        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue

        # Adjust stats based on protocol
        # Note: raw stats counters in stats class
        if parsed.has_tcp:
            stats.tcp_packets += 1
        elif parsed.has_udp:
            stats.udp_packets += 1

        tuple_key = FiveTuple(
            src_ip=parse_ip(parsed.src_ip),
            dst_ip=parse_ip(parsed.dest_ip),
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol
        )

        # Build packet job dict
        pkt_job = {
            'ts_sec': raw['ts_sec'],
            'ts_usec': raw['ts_usec'],
            'tuple': tuple_key,
            'data': raw['data'],
            'payload_offset': len(raw['data']) - parsed.payload_length,
            'payload_length': parsed.payload_length
        }

        # Consistent hash based on FiveTuple to select Load Balancer
        lb_idx = abs(hash(tuple_key)) % num_lbs
        lbs[lb_idx].input_queue.push(pkt_job)

    print(f"[Reader] Done reading {stats.total_packets} packets")

    # Graceful shutdown pipeline
    # Wait for LBs to process their queues
    for lb in lbs:
        while lb.input_queue.queue.qsize() > 0:
            time.sleep(0.01)
        lb.stop()

    # Wait for FPs to process their queues
    for fp in fps:
        while fp.input_queue.queue.qsize() > 0:
            time.sleep(0.01)
        fp.stop()

    # Stop output writer
    writer_state['running'] = False
    writer_thread.join()

    # Clean up files
    reader.close()
    writer.close()

    # Print final processing report
    print("\n")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {stats.total_packets:<10}                             ║")
    print(f"║ Total Bytes:        {stats.total_bytes:<10}                             ║")
    print(f"║ TCP Packets:        {stats.tcp_packets:<10}                             ║")
    print(f"║ UDP Packets:        {stats.udp_packets:<10}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Forwarded:          {stats.forwarded:<10}                             ║")
    print(f"║ Dropped:            {stats.dropped:<10}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║ THREAD STATISTICS                                            ║")
    
    for lb in lbs:
        print(f"║   LB{lb.id} dispatched:      {lb.dispatched_count:<10}                             ║")
    for fp in fps:
        print(f"║   FP{fp.id} processed:       {fp.processed_count:<10}                             ║")
        
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                   APPLICATION BREAKDOWN                      ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    # Sort and print apps by count descending
    sorted_apps = sorted(stats.app_counts.items(), key=lambda x: x[1], reverse=True)
    for app, count in sorted_apps:
        pct = 100.0 * count / stats.total_packets if stats.total_packets > 0 else 0.0
        bar_len = int(pct / 5)
        bar = "#" * bar_len
        app_str = appTypeToString(app)
        
        # Format matching the C++ layout:
        left_part = f"║ {app_str:<15} {count:>8} {pct:>5.1f}% {bar:<20}"
        print(f"{left_part:<62}║")

    print("╚══════════════════════════════════════════════════════════════╝")

    # List unique SNIs
    print("\n[Detected Domains/SNIs]")
    for sni, app in sorted(stats.detected_snis.items()):
        print(f"  - {sni} -> {appTypeToString(app)}")

    print(f"\nOutput written to: {output_file}\n")

if __name__ == '__main__':
    main()
