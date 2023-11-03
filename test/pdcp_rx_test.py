import unittest

from bcc import BPF, libbcc
import ctypes
from scapy.all import *


class PacketDropTestCase(unittest.TestCase):
    bpf = None
    func = None

    DATA_OUT_LEN = 1514

    def _run_test(self, data, data_out_expect, retval_expect, repeat=1):
        size = len(data)
        data = ctypes.create_string_buffer(raw(data), size)
        data_out = ctypes.create_string_buffer(self.DATA_OUT_LEN)
        size_out = ctypes.c_uint32()
        retval = ctypes.c_uint32()
        duration = ctypes.c_uint32()

        ret = libbcc.lib.bpf_prog_test_run(self.func.fd, repeat,
                                           ctypes.byref(data), size,
                                           ctypes.byref(data_out),
                                           ctypes.byref(size_out),
                                           ctypes.byref(retval),
                                           ctypes.byref(duration))
        self.assertEqual(ret, 0)

        self.assertEqual(retval.value, retval_expect)
        if data_out_expect:
            self.assertEqual(data_out[:size_out.value], raw(data_out_expect))

    def setUp(self):
        self.bpf = BPF(src_file=b"./xdp_pdcp_rx.c", hdr_file=b"./ciphering.h")
        self.func = self.bpf.load_func(b"xdp_prog_simple", BPF.XDP)

    def test_ipv4_tcp_80(self):
        packet_in = Ether() / IP() / TCP(dport=80)
        self._run_test(packet_in, None, BPF.XDP_DROP)

    def test_ipv4_udp_80(self):
        packet_in = Ether() / IP() / UDP(dport=80)
        self._run_test(packet_in, packet_in, BPF.XDP_PASS)

    def test_ipv4_tcp_443(self):
        packet_in = Ether() / IP() / TCP(dport=443)
        self._run_test(packet_in, packet_in, BPF.XDP_PASS)

    def test_ipv6_tcp_80(self):
        packet_in = Ether() / IPv6() / TCP(dport=443)
        self._run_test(packet_in, packet_in, BPF.XDP_PASS)


if __name__ == '__main__':
    unittest.main()