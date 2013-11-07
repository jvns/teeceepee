"""
Unit tests for TCPSocket.

Mocks a listener instead of sending real packets.

"""

from tcp import TCPSocket
from scapy.all import IP, TCP, Ether
from mock_listener import MockListener


def test_handshake():
    listener = MockListener()
    conn = TCPSocket(listener, "localhost", 80)
    initial_seq = conn.seq

    tcp_packet = TCP(dport=conn.src_port, flags="SA", seq=100, ack=initial_seq + 1)
    syn_ack = Ether() / IP(dst=conn.src_ip) / tcp_packet
    listener.dispatch(syn_ack)

    assert conn.seq == initial_seq + 1
    assert conn.state == "ESTABLISHED"
