#!/usr/bin/env ipython

FAKE_IP = "10.0.4.4"
MAC_ADDR = "60:67:20:eb:7b:bc"
from scapy.all import srp, Ether, ARP

for _ in range(4):
    srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=FAKE_IP, hwsrc=MAC_ADDR))

from tcp import TCPSocket
import tcp

def test_handshake():
    conn = TCPSocket("example.com", 80, FAKE_IP)
    initial_seq = conn.seq
    conn.handshake()
    assert conn.seq == initial_seq + 1

def test_send_data():
    payload = "GET / HTTP/1.0\r\n\r\n"
    conn = TCPSocket("google.com", 80, FAKE_IP)
    conn.handshake()
    conn.send(payload)
    data = conn.recv()
    assert len(data) > 5

def test_open_socket():
    conn = TCPSocket("example.com", 80, FAKE_IP)

