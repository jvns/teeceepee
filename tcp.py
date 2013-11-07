from scapy.all import TCP, IP, send
from tcp_listener import TCPListener
import random
from Queue import Queue

listener = TCPListener("10.0.4.4")
listener.start_daemon()

class TCPSocket(object):
    def __init__(self, dest_ip, dest_port,
                 src_ip='127.0.0.1', verbose=0):
        self.verbose = verbose
        self.ip_header = IP(dst=dest_ip, src=src_ip)
        self.dest_port = dest_port
        self.src_port = listener.get_port()
        self.seq = random.randint(0, 100000)
        self.recv_queue = Queue()
        self.state = "CLOSED"
        print "Initial sequence: ", self.seq

        listener.open(src_ip, self.src_port, self)

        self.send_syn()

    def send_syn(self):
        syn_pkt = self.ip_header / TCP(dport=self.dest_port, sport=self.src_port, flags="S", seq=self.seq)
        send(syn_pkt, verbose=self.verbose)
        self.state = "SYN-SENT"

    def close(self):
        src_ip, src_port = self.ip_header.src, self.src_port
        listener.close(src_ip, src_port)

    @staticmethod
    def create_ack(packet):
        return TCP(dport=packet.sport,
                   sport=packet.dport,
                   seq=packet.ack,
                   ack=packet.seq + 1,
                   flags="A")

    def send_ack(self, packet):
        ack_pkt = self.ip_header / self.create_ack(packet)
        send(ack_pkt, verbose=self.verbose)
        self.seq, self.ack = ack_pkt.seq, ack_pkt.ack

    def handle(self, packet):
        print "Handling:",
        print packet.summary()
        if packet.sprintf("%TCP.flags%") == 'FA':
            self.send_ack(packet)
            self.state = "CLOSED"
            return
        if self.state == "SYN-SENT":
            self.send_ack(packet)
            self.state = "ESTABLISHED"
            return

    def send(self, payload):
        pass

    def recv(self):
        # Block until everything is received
        return ""


