from scapy.all import TCP, IP, sr1, send, sniff
import random
from Queue import Queue
import threading

source_port = random.randint(12345, 50000)
open_sockets = {}

class TCPSocket(object):
    def __init__(self, dest_ip, dest_port,
                 src_ip='127.0.0.1', verbose=0):
        global source_port
        global open_sockets
        open_sockets[dest_ip, dest_port] = self
        source_port += 1
        self.verbose = verbose
        self.ip_header = IP(dst=dest_ip, src=src_ip)
        self.dest_port = dest_port
        self.src_port = source_port
        self.seq = random.randint(0, 100000)
        self.recv_queue = Queue()

    def close(self):
        dest_ip, dest_port = self.ip_header.dst.repr, self.dest_port
        del open_sockets[dest_ip, dest_port]

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
        self.seq, self.ack = ack_pkt.seq, ack_pkt.ack
        send(ack_pkt, verbose=self.verbose)

    def send(self, payload):
        pass

    def recv(self):
        # Block until everything is received
        return ""

def dispatch(pkt):
    print pkt.summary()

def listen(ip_address, iface="wlan0"):
    filter_rule = "tcp and ip dst %s" % ip_address
    sniff(filter=filter_rule, iface=iface, prn=dispatch, store=0)

def start_daemon(ip_address):
    t = threading.Thread(target=listen, args=[ip_address])
    t.daemon=True
    t.start()

start_daemon("10.0.4.4")
