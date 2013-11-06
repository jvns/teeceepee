#!/usr/bin/env ipython

FAKE_IP = "10.0.4.4"
MAC_ADDR = "60:67:20:eb:7b:bc"
from scapy.all import srp, Ether, ARP

for _ in range(4):
    srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=FAKE_IP, hwsrc=MAC_ADDR))

from tcp import TCPConn

def test_handshake():
    conn = TCPConn(80, "example.com", FAKE_IP)
    initial_seq = conn.seq
    conn.handshake()
    assert conn.seq == initial_seq + 1

def test_send_data():
    payload = "GET / HTTP/1.0\r\n\r\n"
    conn = TCPConn(80, "google.com", FAKE_IP)
    conn.handshake()
    conn.send(payload)
    data = conn.recv()
    assert len(data) > 5

