# Tell scapy not to log warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
import socket
import fcntl
import struct 
import time
from scapy.all import srp, Ether, ARP
sys.path.insert(0, ".")
from teeceepee.tcp import TCPSocket
from teeceepee.tcp_listener import TCPListener

# This needs to be in your subnet, and not your IP address.
# Try something like 10.0.4.4 or 192.168.8.8

def arp_spoof(fake_ip, mac_address):
    try:
        for _ in xrange(5):
            srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=fake_ip, hwsrc=mac_address), verbose=0, timeout=0.05)
            time.sleep(0.05)
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

def get_page(url, fake_ip):
    hostname, path = parse(url)
    request = "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n" % (path, hostname)
    listener = TCPListener(fake_ip)
    conn = TCPSocket(listener)

    conn.connect(hostname, 80)
    conn.send(request)
    data = conn.recv(10000)
    conn.close()
    return data

def get_mac_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

if __name__ == "__main__":
    # If your local IP address is something like
    # 192.168.0.1 - choose 192.168.4.4 or something
    # 10.0.1.1 - choose 10.0.4.4 or something
    # The IP address you choose should be one that nobody else has!
    # Be careful.
    FAKE_IP = "10.0.4.4" 
    # You need to specify your interface here
    MAC_ADDR = get_mac_address("wlan0")
    arp_spoof(FAKE_IP, MAC_ADDR)
    if len(sys.argv) != 2:
        print "Usage: sudo python wget.py some-site.com"
        sys.exit(1)
    contents = get_page(sys.argv[1], FAKE_IP)
    print contents
