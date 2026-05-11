from scapy.all import sniff, ARP
from datetime import datetime

ip_mac_table = {}

packet_count = 0

LOG_FILE = "packet_logs.txt"


def banner():
    print("=" * 60)
    print(" Advanced Packet Sniffer + ARP Spoofing Detector")
    print(" Using Python + Scapy")
    print("=" * 60)


def log_message(message):
    with open(LOG_FILE, "a") as file:
        file.write(message + "\n")


def detect_arp_spoof(packet):

    global packet_count

    if packet.haslayer(ARP):

        packet_count += 1

        arp_layer = packet[ARP]

        ip_address = arp_layer.psrc
        mac_address = arp_layer.hwsrc

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("\n[ARP PACKET DETECTED]")
        print(f"Time       : {current_time}")
        print(f"IP Address : {ip_address}")
        print(f"MAC Address: {mac_address}")
        print(f"Packet No. : {packet_count}")

        log_message(
            f"[{current_time}] "
            f"IP: {ip_address} | "
            f"MAC: {mac_address}"
        )

        if ip_address in ip_mac_table:

            existing_mac = ip_mac_table[ip_address]

            if existing_mac != mac_address:

                print("\n" + "!" * 60)
                print("[WARNING] POSSIBLE ARP SPOOFING DETECTED!")
                print(f"IP Address : {ip_address}")
                print(f"Old MAC    : {existing_mac}")
                print(f"New MAC    : {mac_address}")
                print("!" * 60)

                log_message(
                    f"[ALERT] ARP Spoofing Detected -> "
                    f"IP: {ip_address}, "
                    f"Old MAC: {existing_mac}, "
                    f"New MAC: {mac_address}"
                )

        else:
            ip_mac_table[ip_address] = mac_address


def start_sniffing(interface=None):

    print("\n[*] Starting ARP packet sniffing...")
    print("[*] Press CTRL + C to stop\n")

    sniff(
        iface=interface,
        filter="arp",
        prn=detect_arp_spoof,
        store=False
    )


def main():

    banner()

    print("\n1. Start Sniffing")
    print("2. Exit")

    choice = input("\nEnter choice: ")

    if choice == "1":

        interface = input(
            "Enter interface (Leave blank for default): "
        )

        if interface.strip() == "":
            interface = None

        try:
            start_sniffing(interface)

        except PermissionError:
            print("\n[ERROR] Run as root/admin.")

        except KeyboardInterrupt:
            print("\n[+] Sniffing stopped.")

        except Exception as e:
            print(f"\n[ERROR] {e}")

    elif choice == "2":
        print("Exiting...")

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
