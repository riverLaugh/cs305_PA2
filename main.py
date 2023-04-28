from scapy.layers.inet import TCP, IP
from scapy.utils import rdpcap


def group_tcp_packets(file, savefile, client_ip_prev, server_ip_prev, client_port_prev, server_port_prev):
    # Define custom filter function
    def custom_filter(packet):
        return packet.haslayer(IP) and packet.haslayer(TCP) and \
               (((packet[IP].src == client_ip_prev and packet[IP].dst == server_ip_prev) and
                 (packet[TCP].sport == client_port_prev and packet[TCP].dport == server_port_prev))
                or ((packet[IP].src == server_ip_prev and packet[IP].dst == client_ip_prev) and
                    (packet[TCP].sport == server_port_prev and packet[TCP].dport == client_port_prev)))

    def custom_filter_cs(packet):
        return ((packet[IP].src == client_ip_prev and packet[IP].dst == server_ip_prev) and
                (packet[TCP].sport == client_port_prev and packet[TCP].dport == server_port_prev))

    def custom_filter_sc(packet):
        return (((packet[IP].src == server_ip_prev and packet[IP].dst == client_ip_prev) and
                 (packet[TCP].sport == server_port_prev and packet[TCP].dport == client_port_prev)))

    def isSYN(packet):
        if packet.flags & 0x02:
            return True
        else:
            return False

    # Read packets from pcap file
    packets = rdpcap(file)
    filtered_packets = list(filter(custom_filter, packets))
    # Sort packets within each TCP stream by their sequence number
    filtered_packets = sorted(filtered_packets, key=lambda pkt: pkt[TCP].seq)
    cs_seq_start = 0
    sc_seq_start = 0
    csfound = False
    scfound =False
    for packet in filtered_packets:
        if (custom_filter_cs(packet) and isSYN(packet) and not csfound):
            cs_seq_start = packet.getlayer(TCP).seq + 1
            csfound = True
        if (custom_filter_sc(packet) and isSYN(packet) and not scfound):
            sc_seq_start = packet.getlayer(TCP).seq + 1
            scfound = True
    with open(savefile, 'w') as f:
        s = f"Server: {server_ip_prev}:{server_port_prev} <-> Client: {client_ip_prev}:{client_port_prev}\n"
        f.write(s)
        count = 0
        for packet in filtered_packets:
            if (custom_filter_cs(packet)):
                seq = packet.getlayer(TCP).seq - cs_seq_start
                ack = packet.getlayer(TCP).ack - cs_seq_start
                flags = ''
                if packet.flags & 0x02:
                    flags += "S"
                if packet.flags & 0x01:
                    flags += "F"
                if packet.flags & 0x10:
                    flags += "A"
                count += 1
                s = f"Client -> Server Num: {count}, SEQ: {seq}, ACK: {ack} {flags}\n"
                f.write(s)
                pass
            if (custom_filter_sc(packet)):
                seq = packet.getlayer(TCP).seq - sc_seq_start
                ack = packet.getlayer(TCP).ack - sc_seq_start
                count += 1
                flags = ''
                if packet.flags & 0x02:
                    flags += "S"
                if packet.flags & 0x01:
                    flags += "F"
                if packet.flags & 0x10:
                    flags += "A"
                s = f"Server -> Client Num: {count}, SEQ: {seq}, ACK: {ack} {flags}\n"
                f.write(s)
                pass
