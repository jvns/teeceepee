import sys
import socket
from scapy.all import srp, Ether, ARP
sys.path.insert(0, ".")
from teeceepee.tcp import TCPSocket


FAKE_IP = "10.0.4.4"
MAC_ADDR = "60:67:20:eb:7b:bc"
def arp_spoof():
    try:
        for _ in range(4):
            srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=FAKE_IP, hwsrc=MAC_ADDR), verbose=0)
        listener = TCPListener(FAKE_IP)
    except socket.error:
        # Are you sure you're running as root?
        print ""
        print "ERROR: You need to run this script as root."
        sys.exit(1)


def test_get_google_homepage():
    if not RUN: raise SkipTest
    payload = "GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % google_ip
    conn = LoggingTCPSocket(listener)

    conn.connect(google_ip, 80)
    conn.send(payload)
    time.sleep(3)
    data = conn.recv()
    conn.close()
    time.sleep(3)

    assert "google" in data
    assert conn.state == "CLOSED"
    assert len(conn.received_packets) >= 4
    packet_flags = [p.sprintf("%TCP.flags%") for p in conn.received_packets]
    assert packet_flags[0] == "SA"
    assert "F" in packet_flags[-2]
    assert packet_flags[-1] == "A"
    assert "PA" in packet_flags

    assert conn.states == ["CLOSED", "SYN-SENT", "ESTABLISHED", "LAST-ACK", "CLOSED"]

if __name__ == "__main__":
    arp_spoof()
