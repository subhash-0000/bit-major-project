import requests
from scapy.all import sniff, IP, TCP, get_if_list, get_if_addr, conf
import time
import socket
from collections import defaultdict
import threading
import json
import os

# Backend endpoint for alert creation
BACKEND_URL = 'http://localhost:5000/process_alert'  # Change if backend runs elsewhere

# Simple detection: flag multiple TCP SYN packets from same IP (possible port scan)
SYN_COUNTS = {}
THRESHOLD = 10  # Number of SYNs per minute to trigger alert
WINDOW = 60  # seconds
PORT_SETS = defaultdict(list)  # track (timestamp, dport) per src
PORT_THRESHOLD = 20  # unique destination ports in window -> port scan
RST_COUNTS = {}
RST_THRESHOLD = 50  # RSTs in window -> possible scanning or reset flood
ALERT_COOLDOWN = 60  # seconds between alerts for same src/type
LAST_ALERT = {}  # (src, alert_type) -> timestamp

# Offline queue settings
ALERT_QUEUE_FILE = os.path.join(os.path.dirname(__file__), 'alerts_queue.jsonl')
RETRY_INTERVAL = 30  # seconds between retry attempts

# Example blacklist (replace with your own list or fetch from file/service)
BLACKLIST = set(["1.2.3.4", "5.6.7.8"])


def send_alert(message):
    data = {'message': message}
    try:
        resp = requests.post(BACKEND_URL, json=data)
        print(f"Alert sent: {message} | Response: {resp.status_code}")
    except Exception as e:
        print(f"Failed to send alert: {e}")
        # Save to offline queue for later retry
        try:
            entry = {'ts': int(time.time()), 'message': message}
            with open(ALERT_QUEUE_FILE, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(entry) + "\n")
            print(f"Queued alert to {ALERT_QUEUE_FILE}")
        except Exception as ex:
            print(f"Failed to queue alert: {ex}")


def _retry_queued_alerts():
    while True:
        try:
            if not os.path.exists(ALERT_QUEUE_FILE):
                time.sleep(RETRY_INTERVAL)
                continue
            lines = []
            with open(ALERT_QUEUE_FILE, 'r', encoding='utf-8') as fh:
                lines = [l.strip() for l in fh if l.strip()]

            if not lines:
                time.sleep(RETRY_INTERVAL)
                continue

            remaining = []
            for line in lines:
                try:
                    entry = json.loads(line)
                    resp = requests.post(BACKEND_URL, json={'message': entry.get('message')} , timeout=5)
                    if resp.status_code == 200:
                        print(f"Retried alert delivered: {entry.get('message')}")
                    else:
                        print(f"Retry failed, server returned {resp.status_code}")
                        remaining.append(line)
                except Exception as e:
                    print(f"Retry exception: {e}")
                    remaining.append(line)

            # overwrite queue with remaining
            if remaining:
                with open(ALERT_QUEUE_FILE, 'w', encoding='utf-8') as fh:
                    fh.write('\n'.join(remaining) + '\n')
            else:
                try:
                    os.remove(ALERT_QUEUE_FILE)
                except Exception:
                    pass

        except Exception as e:
            print(f"Alert retry loop error: {e}")

        time.sleep(RETRY_INTERVAL)


def detect_syn(packet):
    if packet.haslayer(TCP):
        src = packet[IP].src if packet.haslayer(IP) else 'N/A'
        dst = packet[IP].dst if packet.haslayer(IP) else 'N/A'
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        print(f"Captured TCP packet: {src}:{sport} -> {dst}:{dport} | Flags: {flags}")
        now = int(time.time())

        # Blacklist check
        if src in BLACKLIST or dst in BLACKLIST:
            key = (src, 'blacklist')
            last = LAST_ALERT.get(key, 0)
            if now - last > ALERT_COOLDOWN:
                send_alert(f"Traffic involving blacklisted IP detected: {src} -> {dst} | port {dport} | flags {flags}")
                LAST_ALERT[key] = now

        # SYN detection (possible scans)
        if 'S' in str(flags):
            if src not in SYN_COUNTS:
                SYN_COUNTS[src] = []
            # keep timestamps in window
            SYN_COUNTS[src] = [t for t in SYN_COUNTS[src] if now - t < WINDOW]
            SYN_COUNTS[src].append(now)
            if len(SYN_COUNTS[src]) > THRESHOLD:
                key = (src, 'syn_scan')
                last = LAST_ALERT.get(key, 0)
                if now - last > ALERT_COOLDOWN:
                    send_alert(f"Possible SYN port scan detected from {src} (SYNs={len(SYN_COUNTS[src])} in {WINDOW}s)")
                    LAST_ALERT[key] = now
                SYN_COUNTS[src] = []  # Reset after alert

        # Track unique destination ports per source for horizontal port scans
        try:
            # store (timestamp, dport)
            PORT_SETS[src] = [entry for entry in PORT_SETS[src] if now - entry[0] < WINDOW]
            PORT_SETS[src].append((now, dport))
            unique_ports = set(p for _, p in PORT_SETS[src])
            if len(unique_ports) > PORT_THRESHOLD:
                key = (src, 'many_dports')
                last = LAST_ALERT.get(key, 0)
                if now - last > ALERT_COOLDOWN:
                    send_alert(f"Possible horizontal port scan from {src} hitting {len(unique_ports)} unique ports in {WINDOW}s")
                    LAST_ALERT[key] = now
                PORT_SETS[src] = []
        except Exception:
            pass

        # RST flood / many resets detection
        if 'R' in str(flags):
            if src not in RST_COUNTS:
                RST_COUNTS[src] = []
            RST_COUNTS[src] = [t for t in RST_COUNTS[src] if now - t < WINDOW]
            RST_COUNTS[src].append(now)
            if len(RST_COUNTS[src]) > RST_THRESHOLD:
                key = (src, 'rst_flood')
                last = LAST_ALERT.get(key, 0)
                if now - last > ALERT_COOLDOWN:
                    send_alert(f"High number of RST packets from {src} ({len(RST_COUNTS[src])} in {WINDOW}s) - possible scan or reset flood")
                    LAST_ALERT[key] = now
                RST_COUNTS[src] = []


def get_active_interface():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"[INFO] Hostname: {hostname}")
    print(f"[INFO] Local IP address: {local_ip}")
    print("[INFO] Try to match this IP with the interface list above.")


def auto_detect_interface():
    """Try to find the best interface to sniff on:
    1. Use Scapy route to get default interface
    2. Match local IP to interface addresses
    Returns interface name (or None)
    """
    try:
        # Try Scapy route to get default iface
        route = conf.route.route("0.0.0.0")
        # route may be (dst, gw, iface) or (dst, iface, gw) depending on Scapy version
        iface_candidate = None
        if isinstance(route, (list, tuple)) and len(route) >= 3:
            # prefer the element that looks like an interface name
            for part in route:
                if isinstance(part, str) and part.startswith("\\Device\\NPF_"):
                    iface_candidate = part
                    break
            if not iface_candidate:
                # fallback to third element
                iface_candidate = route[2]
        if iface_candidate:
            print(f"[INFO] Auto-detected interface from route: {iface_candidate}")
            return iface_candidate
    except Exception as e:
        print(f"[WARN] Could not auto-detect via route: {e}")

    # Fallback: match local IP to interface list
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
                if addr == local_ip:
                    print(f"[INFO] Matched local IP to interface: {iface} -> {addr}")
                    return iface
            except Exception:
                # some interfaces won't have an address; skip
                continue
    except Exception as e:
        print(f"[WARN] Error while matching interface by IP: {e}")

    print("[INFO] No auto-detected interface found")
    return None


def main():
    print("[*] Listing available network interfaces:")
    interfaces = get_if_list()
    for idx, iface_name in enumerate(interfaces):
        print(f"  [{idx}] {iface_name}")

    # 1) Try auto-detection
    print("[*] Attempting automatic interface detection...")
    iface = auto_detect_interface()

    # 2) If auto-detect didn't return a usable iface, iterate and test each
    def try_test(iface_to_test):
        try:
            pkts = sniff(filter="tcp", count=3, timeout=4, iface=iface_to_test)
            return len(pkts)
        except Exception as e:
            print(f"[DEBUG] Test capture on {iface_to_test} failed: {e}")
            return 0

    if iface:
        print(f"[*] Testing auto-detected interface: {iface}")
        cnt = try_test(iface)
        if cnt > 0:
            print(f"[OK] Auto-detected interface {iface} captured {cnt} packets.")
        else:
            print(f"[WARN] Auto-detected interface {iface} captured 0 packets. Will try other interfaces.")
            iface = None

    if not iface:
        print("[*] Scanning interfaces to find one that sees traffic...")
        for iface_candidate in interfaces:
            if iface_candidate.lower().endswith('loopback'):
                continue
            print(f"[*] Testing interface: {iface_candidate}")
            cnt = try_test(iface_candidate)
            if cnt > 0:
                iface = iface_candidate
                print(f"[OK] Selected interface {iface} which captured {cnt} packets.")
                break

    if not iface:
        print("[WARN] No interface captured packets during quick tests. You can try generating traffic (browse/ping) or run the script interactively to pick another interface.")

    print("[*] Starting network monitor (IDS)... Press Ctrl+C to stop.")
    try:
        sniff(filter="tcp", prn=detect_syn, store=0, iface=iface)
    except Exception as e:
        print(f"[ERROR] Live sniffing failed: {e}")


if __name__ == "__main__":
    get_active_interface()
    main()
