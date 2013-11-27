# WARNING: This does not work yet
import sys
import socket
import time
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
            time.sleep(0.1)
        listener = TCPListener(FAKE_IP)
    except socket.error:
        # Are you sure you're running as root?
        print ""
        print "ERROR: You need to run this script as root."
        sys.exit(1)

def parse(url):
    """
    Parses an URL and returns the hostname and the rest
    """
    # We *definitely* don't support https
    if 'https' in url:
        print "We don't support https."
        sys.exit(1)
    if '://' in url:
        url = url.split('://')[1]

    parts = url.split('/')
    hostname = parts[0]
    path = '/' + '/'.join(parts[1:])
    return hostname, path

def get_page(url):
    print "Getting", url
    hostname, path = parse(url)
    request = "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n" % (path, hostname)
    listener = TCPListener(FAKE_IP)
    conn = TCPSocket(listener)

    conn.connect(hostname, 80)
    conn.send(request)
    time.sleep(5)
    data = conn.recv()
    conn.close()
    time.sleep(1)
    return data

if __name__ == "__main__":
    print "This program is not working yet =(\n"
    if len(sys.argv) != 2:
        print "Usage: sudo python wget.py some-site.com"
        sys.exit(1)
    arp_spoof()
    contents = get_page(sys.argv[1])
    print contents
