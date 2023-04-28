from scapy.all import *
from scapy.layers.http import HTTP, HTTPResponse
from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6

conf.verb = 0

'''
This is the skeleton code for the packet analyzer. You will need to complete the functions below. Note that 
you cannot modify the function signatures. You can add additional functions if you wish.
'''


def packet_info(pcap_file, save_file):
    # TCP 连接代码
    '''
    :param pcap_file: path to pcap file
    :param save_file: path to save file of results
    :return: not specified
    '''
    packets = rdpcap(pcap_file)
    processed_connections = set()
    with open(save_file, 'w') as f:
        for packet in packets:
            if packet.haslayer(TCP) and packet.haslayer(IP) :
                src_port = packet.getlayer(TCP).sport
                dst_port = packet.getlayer(TCP).dport
                if packet.haslayer(IP):
                    src_ip = packet.getlayer(IP).src
                    dst_ip = packet.getlayer(IP).dst
                connection = (src_ip, dst_ip, src_port, dst_port)
                if connection in processed_connections:
                    continue
                # write to file and add this connection to the processed set
                f.write(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
                processed_connections.add(connection)
        # Check if the packet is an IP packet


# iterate over each packet in the pcap file
def tcp_stream_analyzer(file, savefile, client_ip_prev, server_ip_prev, client_port_prev, server_port_prev):
    def custom_filter(packet):
        return (packet.haslayer(IPv6) or packet.haslayer(IP)) and packet.haslayer(TCP) and \
            (((packet.haslayer(IP) and packet[IP].src == client_ip_prev and packet[IP].dst == server_ip_prev) or
              (packet.haslayer(IPv6) and packet[IPv6].src == client_ip_prev and packet[IPv6].dst == server_ip_prev)) and
             ((packet[TCP].sport == client_port_prev and packet[TCP].dport == server_port_prev)) or
             (((packet.haslayer(IP) and packet[IP].src == server_ip_prev and packet[IP].dst == client_ip_prev) or
              (packet.haslayer(IPv6) and packet[IPv6].src == server_ip_prev and packet[IPv6].dst == client_ip_prev)) and
                 ((packet[TCP].sport == server_port_prev and packet[TCP].dport == client_port_prev))))

    def custom_filter_cs(packet):
        return (((packet.haslayer(IP) and packet[IP].src == client_ip_prev and packet[IP].dst == server_ip_prev) or
              (packet.haslayer(IPv6) and packet[IPv6].src == client_ip_prev and packet[IPv6].dst == server_ip_prev)) and
                (packet[TCP].sport == client_port_prev and packet[TCP].dport == server_port_prev))

    def custom_filter_sc(packet):
        return (((packet.haslayer(IP) and packet[IP].src == server_ip_prev and packet[IP].dst == client_ip_prev) or
               (packet.haslayer(IPv6) and packet[IPv6].src == server_ip_prev and packet[IPv6].dst == client_ip_prev)) and
                (packet[TCP].sport == server_port_prev and packet[TCP].dport == client_port_prev))

    def isSYN(packet):
        return packet.getlayer(TCP).flags & 0x02

    packets = rdpcap(file)
    filtered_packets = list(filter(custom_filter, packets))
    sc_start_seq = 0
    cs_start_seq = 0
    for p in filtered_packets:
        if custom_filter_sc(p):
            sc_start_seq = p.getlayer(TCP).seq
            break
    for p in filtered_packets:
        if custom_filter_cs(p):
            cs_start_seq = p.getlayer(TCP).seq
            break
    with open(savefile, 'w') as f:
        s = f"Server : {server_ip_prev}:{server_port_prev} <-> Client : {client_ip_prev}:{client_port_prev}\n"
        f.write(s)
        for i, p in enumerate(filtered_packets):
            if p.haslayer(IP) and p[IP].src == server_ip_prev:
                is_server = True
            elif p.haslayer(IP) and p[IP].src == client_ip_prev:
                is_server = False
            elif p.haslayer(IPv6) and p[IPv6].src == server_ip_prev:
                is_server = True
            elif p.haslayer(IPv6) and p[IPv6].src == client_ip_prev:
                is_server = False
            tcp = p.getlayer(TCP)
            flags = ""
            if tcp.flags & 0x01: flags += "F"
            if tcp.flags & 0x02: flags += "S"
            if tcp.flags & 0x04: flags += "R"
            if tcp.flags & 0x08: flags += "P"
            if tcp.flags & 0x10: flags += "A"
            if tcp.flags & 0x20: flags += "U"
            if tcp.flags & 0x40: flags += "E"
            if tcp.flags & 0x80: flags += "C"
            if is_server:
                seq_num = tcp.seq - sc_start_seq
                ack_num = tcp.ack - cs_start_seq
                if isSYN(p):
                    seq_num = 0
                s = f"Server -> Client Num: {i + 1}, SEQ: {seq_num}, ACK: {ack_num} {flags}\n"
                f.write(s)
            else :
                seq_num = tcp.seq - cs_start_seq
                ack_num = tcp.ack - sc_start_seq
                if isSYN(p):
                    ack_num = 0
                s = f"Client -> Server Num: {i + 1}, SEQ: {seq_num}, ACK: {ack_num} {flags}\n"
                f.write(s)
    f.close()


def http_stream_analyzer(pcapfile, savefile, client_ip_prev, server_ip_prev, client_port_prev):
    """
    :param pcapfile: path to pcap file
    :param savefile: path to save file of analysis results
    :param client_ip_prev: ip address of client of HTTP stream waiting for analysis
    :param server_ip_prev: server ip address of HTTP stream waiting for analysis
    :param client_port_prev: port of client of HTTP stream waiting for analysis
    :return: not specified
    """
    http_stream = ''
    buffer = ''

    def custom_filter(packet):
        return packet.haslayer(IP) and packet.haslayer(TCP)

    packets = rdpcap(pcapfile)
    packets = list(filter(custom_filter, packets))
    with open(savefile, 'w') as f:
        for packet in packets:
            try:
                if packet.getlayer(IP).src == client_ip_prev and packet.getlayer(
                        IP).dst == server_ip_prev and packet.getlayer(TCP).sport == client_port_prev:
                    http = packet.getlayer(TCP).payload
                    a = str(http.Method).replace("b'", "").replace("'", "")
                    b = str(http.Http_Version).replace("b'", "").replace("'", "")
                    c = str(http.Path).replace("b'", "").replace("'", "")
                    f.write(f"{a} {c} {b}\n")
                if packet.getlayer(IP).src == server_ip_prev and packet.getlayer(
                        IP).dst == client_ip_prev and packet.getlayer(TCP).dport == client_port_prev:
                    http = packet.getlayer(TCP).payload.payload
                    a = str(http.Http_Version).replace("b'", "").replace("'", "")
                    b = str(http.Reason_Phrase).replace("b'", "").replace("'", "")
                    c = str(http.Status_Code).replace("b'", "").replace("'", "")
                    f.write(f"{a} {c} {b}\n")
            except AttributeError:
                f.write('..NO HEADER..\n')

        # except:


if __name__ == '__main__':
    # packet_info('TCP_PKTS.pcap', 'tcp_connection.txt')

    # tcp_stream_analyzer('TCP_PKTS.pcap', '2.txt', '52.108.195.3', '10.26.184.140', 443, 7429)
    # tcp_stream_analyzer('TCP_PKTS.pcap', '2.txt', '10.26.184.140', '169.254.169.254', 1294, 80)
    # http_stream_analyzer('Http_.pcap', '3.txt', '10.25.217.154', '113.246.57.9', 53560)

    tcp_stream_analyzer('TCP_PKTS.pcap', '2.txt', '10.26.184.140', '113.240.72.12', 1299, 8081)
    '''
    You can call functions here to test your code.
    '''
# 52.108.195.3:443 -> 10.26.184.140:7429