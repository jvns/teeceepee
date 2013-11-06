from scapy.all import TCP, IP, send, sniff
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
        source_port += 1

        self.verbose = verbose
        self.ip_header = IP(dst=dest_ip, src=src_ip)
        self.dest_port = dest_port
        self.src_port = source_port
        self.seq = random.randint(0, 100000)
        self.recv_queue = Queue()
        self.state = "CLOSED"
        print "Initial sequence: ", self.seq

        open_sockets[src_ip, source_port] = self
        self.send_syn()

    def send_syn(self):
        syn_pkt = self.ip_header / TCP(dport=self.dest_port, sport=self.src_port, flags="S", seq=self.seq)
        send(syn_pkt, verbose=self.verbose)
        self.state = "SYN-SENT"

    def close(self):
        src_ip, src_port = self.ip_header.src, self.src_port
        del open_sockets[src_ip, src_port]

    @staticmethod
    def create_ack(packet):
        return TCP(dport=packet.sport,
                   sport=packet.dport,
                   seq=packet.ack,
                   ack=packet.seq + 1,
                   flags="A")

    def handle(self, packet):
        print "Handling:",
        print packet.summary()
        if self.state == "SYN-SENT":
            syn_ack_pkt = packet
            ack_pkt = self.ip_header / self.create_ack(syn_ack_pkt)
            send(ack_pkt, verbose=self.verbose)
            self.seq, self.ack = ack_pkt.seq, ack_pkt.ack
            self.state = "ESTABLISHED"
            return

    def send(self, payload):
        pass

    def recv(self):
        # Block until everything is received
        return ""

def dispatch(pkt):
    print "Dispatching:",
    print pkt.summary()
    if not isinstance(pkt.payload.payload, TCP):
        return
    ip, port = pkt.payload.dst, pkt.dport
    if (ip, port) not in open_sockets:
        print "Dropping packet!", open_sockets.keys()
        return
    conn = open_sockets[ip, port]
    conn.handle(pkt)

def listen(ip_address, iface="wlan0"):
    filter_rule = "tcp and ip dst %s" % ip_address
    sniff(filter=filter_rule, iface=iface, prn=dispatch, store=0)

def start_daemon(ip_address):
    t = threading.Thread(target=listen, args=[ip_address])
    t.daemon=True
    t.start()

start_daemon("10.0.4.4")
