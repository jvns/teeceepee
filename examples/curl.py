# WARNING: This does not work yet
import sys
import socket
from scapy.all import srp, Ether, ARP
sys.path.insert(0, ".")
from teeceepee.tcp import TCPSocket
from teeceepee.tcp_listener import TCPListener

FAKE_IP = "10.0.4.4" # This needs to be in your subnet
MAC_ADDR = "60:67:20:eb:7b:bc" # This needs to be your MAC address

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


def get_page(hostname):
    print "Getting", hostname
    payload = "GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % hostname
    listener = TCPListener(FAKE_IP)
    conn = TCPSocket(listener)

    conn.connect(hostname, 80)
    conn.send(payload)
    time.sleep(3)
    data = conn.recv()
    conn.close()
    time.sleep(3)

    return data

if __name__ == "__main__":
    print "This program is not working yet =(\n"
    if len(sys.argv) != 2:
        print "Usage: sudo python wget.py some-site.com"
        sys.exit(1)
    arp_spoof()
    contents = get_page(sys.argv[1])
    print contents
