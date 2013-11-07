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

    # We should have sent exactly two packets
    # Check that they look okay
    pkts = listener.received_packets
    assert len(pkts) == 2
    syn, ack = pkts
    assert ack.seq == syn.seq + 1
    assert syn.sprintf("%TCP.flags%") == "S"
    assert ack.sprintf("%TCP.flags%") == "A"
