#!/usr/bin/env python3
import subprocess
import sys
import os

from packet_analyzer_python.dpi_engine.pcap import PcapReader

def run_cmd(cmd):
    print(f"Running: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
    if res.returncode != 0:
        print(f"Error: Command failed with exit code {res.returncode}")
        print(res.stderr)
        sys.exit(1)
    return res.stdout

def main():
    import io
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')
        
    print("=== Verification of C++ to Python Port ===")
    
    # 1. Ensure test_dpi.pcap exists or regenerate it
    if not os.path.exists("test_dpi.pcap"):
        print("Generating test PCAP...")
        run_cmd([sys.executable, "generate_test_pcap.py"])
        
    # 2. Run simple version
    print("\nRunning dpi_simple.py...")
    stdout_simple = run_cmd([
        sys.executable, "dpi_simple.py", 
        "test_dpi.pcap", "output_simple.pcap", 
        "--block-app", "YouTube", 
        "--block-ip", "192.168.1.50"
    ])
    
    # 3. Run multi-threaded version
    print("\nRunning dpi_mt.py...")
    stdout_mt = run_cmd([
        sys.executable, "dpi_mt.py", 
        "test_dpi.pcap", "output_mt.pcap", 
        "--block-app", "YouTube", 
        "--block-ip", "192.168.1.50",
        "--lbs", "2", "--fps", "2"
    ])
    
    # 4. Compare output file sizes and contents
    print("\nComparing output PCAP files...")
    if not os.path.exists("output_simple.pcap") or not os.path.exists("output_mt.pcap"):
        print("Error: Output PCAP files were not generated!")
        sys.exit(1)
        
    size_simple = os.path.getsize("output_simple.pcap")
    size_mt = os.path.getsize("output_mt.pcap")
    
    if size_simple != size_mt:
        print(f"Error: File sizes do not match! Simple: {size_simple} bytes, MT: {size_mt} bytes")
        sys.exit(1)
        
    # Read and sort packets from output_simple.pcap
    reader1 = PcapReader("output_simple.pcap")
    if not reader1.open():
        print("Error: Could not open output_simple.pcap")
        sys.exit(1)
    pkts1 = []
    while True:
        pkt = reader1.read_next_packet()
        if not pkt:
            break
        pkts1.append(pkt)
    reader1.close()
    
    # Read and sort packets from output_mt.pcap
    reader2 = PcapReader("output_mt.pcap")
    if not reader2.open():
        print("Error: Could not open output_mt.pcap")
        sys.exit(1)
    pkts2 = []
    while True:
        pkt = reader2.read_next_packet()
        if not pkt:
            break
        pkts2.append(pkt)
    reader2.close()
    
    # Assert counts
    if len(pkts1) != len(pkts2):
        print(f"Error: Packet counts do not match! Simple: {len(pkts1)}, MT: {len(pkts2)}")
        sys.exit(1)
        
    # Sort packets by (ts_sec, ts_usec, data)
    pkts1_sorted = sorted(pkts1, key=lambda x: (x['ts_sec'], x['ts_usec'], x['data']))
    pkts2_sorted = sorted(pkts2, key=lambda x: (x['ts_sec'], x['ts_usec'], x['data']))
    
    for idx, (p1, p2) in enumerate(zip(pkts1_sorted, pkts2_sorted)):
        if p1['data'] != p2['data']:
            print(f"Error: Packet content mismatch at index {idx}!")
            sys.exit(1)
            
    print("Success: PCAP file contents match exactly (after sorting packets to resolve thread-scheduling reordering)!")
    
    # 5. Verify stats consistency in outputs
    print("\nChecking report consistency...")
    if "Total Packets:      77" not in stdout_simple or "Total Packets:      77" not in stdout_mt:
        print("Error: Total packets processed does not match expected (77)")
        sys.exit(1)
        
    if "Forwarded:          71" not in stdout_simple or "Forwarded:          71" not in stdout_mt:
        print("Error: Forwarded packets count does not match expected (71)")
        sys.exit(1)
        
    if "Dropped:            6" not in stdout_simple or "Dropped:            6" not in stdout_mt:
        print("Error: Dropped packets count does not match expected (6)")
        sys.exit(1)
        
    print("Success: Processing statistics match expected values exactly!")
    print("\nAll checks passed successfully! 🚀")

if __name__ == "__main__":
    main()
