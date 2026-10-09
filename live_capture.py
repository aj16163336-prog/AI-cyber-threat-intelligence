from collections import Counter
import time

from scapy.all import ICMP, IP, TCP, UDP, conf, sniff


def list_interfaces():
    """Return adapter names and descriptions without showing IP/MAC addresses."""
    return [
        (interface.name, interface.description)
        for interface in conf.ifaces.values()
    ]


def capture_summary(interface="Wi-Fi", seconds=20):
    """Capture IP headers briefly and return counts; packet payloads are not stored."""
    stats = {
        "packets": 0,
        "bytes": 0,
        "protocols": Counter(),
        "destination_ips": set(),
        "destination_ports": set(),
    }

    def handle_packet(packet):
        if IP not in packet:
            return

        stats["packets"] += 1
        stats["bytes"] += len(packet)
        stats["destination_ips"].add(packet[IP].dst)

        if TCP in packet:
            protocol = "TCP"
            stats["destination_ports"].add(int(packet[TCP].dport))
        elif UDP in packet:
            protocol = "UDP"
            stats["destination_ports"].add(int(packet[UDP].dport))
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = f"Other IP protocol {packet[IP].proto}"

        stats["protocols"][protocol] += 1

    started = time.monotonic()
    sniff(
        iface=interface,
        filter="ip",
        timeout=int(seconds),
        prn=handle_packet,
        store=False,
    )
    elapsed = max(time.monotonic() - started, 0.001)

    return {
        "interface": interface,
        "duration_seconds": round(elapsed, 1),
        "packets": stats["packets"],
        "bytes": stats["bytes"],
        "packets_per_second": round(stats["packets"] / elapsed, 2),
        "protocols": dict(stats["protocols"]),
        "destination_ips": sorted(stats["destination_ips"]),
        "destination_ports": sorted(stats["destination_ports"]),
    }


if __name__ == "__main__":
    print("Available adapters:")
    for name, description in list_interfaces():
        print(f"{name} - {description}")

    result = capture_summary(seconds=20)
    print("\nCapture finished.")
    print("Total packets:", result["packets"])
    print("Total bytes:", result["bytes"])
    print("Packets per second:", result["packets_per_second"])
    print("Unique destinations:", len(result["destination_ips"]))
    print("Unique destination ports:", len(result["destination_ports"]))
    print("Protocol counts:")
    for protocol, count in result["protocols"].items():
        print(f"{protocol}: {count}")
