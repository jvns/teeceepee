from scapy.all import TCP, IP, sr1, send
import random

source_port = random.randint(12345, 50000)

class TCPConn(object):
    def __init__(self, dest_port, dest_ip,
                 src_ip='127.0.0.1', verbose=0):
        global source_port
        source_port += 1
        self.verbose = verbose
        self.ip_header = IP(dst=dest_ip, src=src_ip)
        self.dest_port = dest_port
        self.src_port = source_port
        self.seq = random.randint(0, 100000)

    @staticmethod
    def create_ack(packet):
        return TCP(dport=packet.sport,
                   sport=packet.dport,
                   seq=packet.ack,
                   ack=packet.seq + 1,
                   flags="A")

    def handshake(self):
        syn_pkt = self.ip_header / TCP(dport=self.dest_port, sport=self.src_port, flags="S", seq=self.seq)
        syn_ack_pkt = sr1(syn_pkt, verbose=self.verbose)
        ack_pkt = self.ip_header / self.create_ack(syn_ack_pkt)
        send(ack_pkt, verbose=self.verbose)
        return syn_ack_pkt

    def send_data(self):
        pass
