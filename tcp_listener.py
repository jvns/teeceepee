import random
import threading
from scapy.all import sniff, TCP, send

class TCPListener(object):
    def __init__(self, ip_address="127.0.0.1"):
        self.ip_address = ip_address
        self.source_port = random.randint(12345, 50000)
        self.open_sockets = {}

    def dispatch(self, pkt):
        if not isinstance(pkt.payload.payload, TCP):
            print "Wrong kind of packet!"
            return
        ip, port = pkt.payload.dst, pkt.dport
        if (ip, port) not in self.open_sockets:
            print "Dropping packet!", self.open_sockets.keys()
            return
        conn = self.open_sockets[ip, port]
        conn.handle(pkt)

    def send(self, packet):
        send(packet)

    def get_port(self):
        # We need to return a new port number to each new connection
        self.source_port += 1
        return self.source_port

    def open(self, ip, port, conn):
        self.open_sockets[ip, port]  = conn

    def close(self, ip, port):
        del self.open_sockets[ip, port]

    def listen(self, iface="wlan0"):
        filter_rule = "tcp and ip dst %s" % self.ip_address
        sniff(filter=filter_rule, iface=iface, prn=self.dispatch, store=0)

    def start_daemon(self):
        t = threading.Thread(target=self.listen)
        t.daemon=True
        t.start()
