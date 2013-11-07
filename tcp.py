from scapy.all import TCP, IP, send
import random
from Queue import Queue
import time

class TCPSocket(object):
    def __init__(self, listener, dest_ip, dest_port,
                 src_ip='127.0.0.1', verbose=0):
        self.verbose = verbose
        self.ip_header = IP(dst=dest_ip, src=src_ip)
        self.dest_port = dest_port
        self.src_port = listener.get_port()
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.seq = random.randint(0, 100000)
        self.recv_queue = Queue()
        self.state = "CLOSED"
        self.listener = listener
        print "Initial sequence: ", self.seq

        self.listener.open(src_ip, self.src_port, self)

        self.send_syn()

    def send_syn(self):
        syn_pkt = self.ip_header / TCP(dport=self.dest_port, sport=self.src_port, flags="S", seq=self.seq)
        self.listener.send(syn_pkt)
        self.state = "SYN-SENT"

    def create_fin_ack(self):
        return TCP(dport=self.dest_port,
                   sport=self.src_port,
                   seq=self.seq,
                   ack=self.ack,
                   flags="FA")

    def close(self):
        self.state = "FIN-WAIT-1"
        self.listener.send(self.create_fin_ack())

    @staticmethod
    def next_seq(packet):
        # really not right.
        if hasattr(packet, 'load'):
            return packet.seq + len(packet.load)
        else:
            return packet.seq + 1

    def create_ack(self, packet):
        return TCP(dport=packet.sport,
                   sport=packet.dport,
                   seq=packet.ack,
                   ack=self.next_seq(packet),
                   flags="A")

    def send_ack(self, packet):
        ack_pkt = self.ip_header / self.create_ack(packet)
        self.listener.send(ack_pkt)
        self.seq, self.ack = ack_pkt.seq, ack_pkt.ack

    def handle(self, packet):
        print "Handling:",
        print packet.summary()
        if self.state == "ESTABLISHED":
            if packet.sprintf("%TCP.flags%") == 'FA':
                self.send_ack(packet)
                self.state = "CLOSED"
                return
        elif self.state == "SYN-SENT":
            self.send_ack(packet)
            self.state = "ESTABLISHED"
            return
        elif self.state == "FIN-WAIT-1":
            if packet.sprintf("%TCP.flags%") == 'FA':
                self.send_ack(packet)
                self.state = "CLOSED"


    def send(self, payload):
        # Block
        while self.state != "ESTABLISHED":
            time.sleep(0.001)
        # Do the actual send
        packet = self.ip_header / TCP(dport=self.dest_port, sport=self.src_port, flags="PA", seq=self.seq, ack=self.ack) / payload
        self.seq += len(payload)
        self.listener.send(packet)

    def recv(self):
        # Block until everything is received
        return ""

