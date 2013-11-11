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
        self.ack = None
        self.dest_ip = dest_ip
        self.seq = random.randint(0, 100000)
        self.recv_queue = Queue()
        self.state = "CLOSED"
        self.listener = listener
        print "Initial sequence: ", self.seq

        self.listener.open(src_ip, self.src_port, self)

        self._send_syn()

    def _send_syn(self):
        self._send(flags="S")
        self.state = "SYN-SENT"

    def _send(self, **kwargs):
        """Every packet we send should go through here."""
        load = kwargs.pop('load', None)
        flags = kwargs.pop('flags', "")
        packet = TCP(dport=self.dest_port,
                     sport=self.src_port,
                     seq=self.seq,
                     ack=self.ack,
                     **kwargs)
        # Always ACK unless it's the first packet
        if self.state == "CLOSED":
            packet.flags = flags
        else:
            packet.flags = flags + "A"
        packet.load = load
        full_packet = self.ip_header / packet
        self.listener.send(full_packet)
        if load is not None:
            self.seq += len(load)

    def _send_ack(self):
        """We actually don't need to do much here!"""
        self._send()

    def close(self):
        self.state = "FIN-WAIT-1"
        self._send(flags="F")

    @staticmethod
    def next_seq(packet):
        # really not right.
        if hasattr(packet, 'load'):
            print "Adding load: ", len(packet.load), "\n"
            return packet.seq + len(packet.load)
        else:
            return packet.seq + 1

    def handle(self, packet):
        # Update our state to indicate that we've received the packet
        self.ack = max(self.next_seq(packet), self.ack)

        print "Handling:",
        print packet.summary()

        tcp_flags = packet.sprintf("%TCP.flags%")

        if self.state == "ESTABLISHED" and 'F' in tcp_flags:
            self.state = "CLOSED"
        elif self.state == "SYN-SENT":
            self.seq += 1
            self.state = "ESTABLISHED"
        elif self.state == "FIN-WAIT-1" and 'F' in tcp_flags:
            self.state = "CLOSED"

        self._send_ack()


    def send(self, payload):
        # Block
        while self.state != "ESTABLISHED":
            time.sleep(0.001)
        # Do the actual send
        self._send(load=payload, flags="P")

    def recv(self):
        # Block until everything is received
        return ""

