import queue
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.modules.setdefault("yaml", SimpleNamespace(safe_load=lambda *_args, **_kwargs: {}))
sys.modules.setdefault("wakeonlan", SimpleNamespace(send_magic_packet=lambda *_args, **_kwargs: None))
sys.modules.setdefault(
    "scapy.all",
    SimpleNamespace(
        ARP=object(),
        DNS=object(),
        ICMP=object(),
        IP=object(),
        conf=SimpleNamespace(sniff_promisc=False, ifaces={}),
        sniff=lambda *_args, **_kwargs: None,
        sr1=lambda *_args, **_kwargs: None,
    ),
)

import dns_wol


class FakeARP:
    def __init__(self, op=1, pdst="", psrc="", hwsrc=""):
        self.op = op
        self.pdst = pdst
        self.psrc = psrc
        self.hwsrc = hwsrc


class FakeIP:
    def __init__(self, src=""):
        self.src = src


class FakeQuestion:
    def __init__(self, qname):
        self.qname = qname


class FakeDNS:
    def __init__(self, qname=b"", qr=0):
        self.qd = FakeQuestion(qname) if qname is not None else None
        self.qr = qr


class FakePacket:
    def __init__(self, arp=None, ip=None, dns=None):
        self._arp = arp
        self._ip = ip
        self._dns = dns

    def __contains__(self, layer):
        if layer is dns_wol.ARP:
            return self._arp is not None
        return False

    def __getitem__(self, layer):
        if layer is dns_wol.ARP:
            return self._arp
        if layer is dns_wol.IP:
            return self._ip
        raise KeyError(layer)

    def getlayer(self, layer):
        if layer is dns_wol.DNS:
            return self._dns
        raise KeyError(layer)

    def haslayer(self, layer):
        if layer is dns_wol.DNS:
            return self._dns is not None
        return False

    def summary(self):
        return "fake-packet"


class DnsWolTests(unittest.TestCase):
    def setUp(self):
        dns_wol.config = SimpleNamespace(
            enable_mail=False,
            from_mail="from@example.org",
            to_mail="to@example.org",
            wait_time=0,
            blocked_ip={"192.168.1.10"},
            local_ip={"127.0.0.1", "192.168.1.2"},
            monitoring_by_ip={
                "192.168.1.50": {
                    "ip": "192.168.1.50",
                    "mac": "aa:bb:cc:dd:ee:ff",
                }
            },
            monitoring_by_dns={
                "server.local": {
                    "dns_name": "server.local",
                    "ip": "192.168.1.50",
                    "mac": "aa:bb:cc:dd:ee:ff",
                }
            },
        )
        dns_wol.work_queue = queue.Queue()
        dns_wol.pending_lock = dns_wol.threading.Lock()
        dns_wol.pending_requests = set()

    def test_add_object_to_thread_queue_skips_duplicate_ip(self):
        first = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="ARP",
            src_ip="192.168.1.20",
        )
        second = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="DNS Query",
            src_ip="192.168.1.30",
            searched_dns="server.local",
        )

        dns_wol.add_object_to_thread_queue(first)
        dns_wol.add_object_to_thread_queue(second)

        self.assertEqual(dns_wol.work_queue.qsize(), 1)
        queued = dns_wol.work_queue.get_nowait()
        self.assertEqual(queued.src_ip, "192.168.1.20")

    def test_arp_check_ignores_local_requestor(self):
        packet = FakePacket(
            arp=FakeARP(op=1, pdst="192.168.1.50", psrc="192.168.1.2", hwsrc="00:11"),
        )

        dns_wol.arp_check(packet)

        self.assertTrue(dns_wol.work_queue.empty())

    def test_arp_check_enqueues_remote_requestor(self):
        packet = FakePacket(
            arp=FakeARP(op=1, pdst="192.168.1.50", psrc="192.168.1.20", hwsrc="00:11"),
        )

        dns_wol.arp_check(packet)

        queued = dns_wol.work_queue.get_nowait()
        self.assertEqual(queued.request_type, "ARP")
        self.assertEqual(queued.src_ip, "192.168.1.20")

    def test_dns_query_check_ignores_local_source(self):
        packet = FakePacket(
            ip=FakeIP(src="192.168.1.2"),
            dns=FakeDNS(qname=b"server.local.", qr=0),
        )

        dns_wol.dns_query_check(packet)

        self.assertTrue(dns_wol.work_queue.empty())

    def test_dns_query_check_enqueues_monitored_query(self):
        packet = FakePacket(
            ip=FakeIP(src="192.168.1.30"),
            dns=FakeDNS(qname=b"server.local.", qr=0),
        )

        dns_wol.dns_query_check(packet)

        queued = dns_wol.work_queue.get_nowait()
        self.assertEqual(queued.request_type, "DNS Query")
        self.assertEqual(queued.searched_dns, "server.local")

    def test_discover_local_ipv4_addresses_collects_interface_and_hostname_ips(self):
        fake_ifaces = {
            "eth0": SimpleNamespace(ip="192.168.1.2"),
            "lo": SimpleNamespace(ip="127.0.0.1"),
            "ipv6": SimpleNamespace(ip="fe80::1"),
        }
        fake_addrinfo = [
            (None, None, None, None, ("192.168.1.3", 0)),
            (None, None, None, None, ("192.168.1.2", 0)),
        ]

        with patch.object(dns_wol.conf, "ifaces", fake_ifaces), patch.object(
            dns_wol.socket, "getaddrinfo", return_value=fake_addrinfo
        ):
            local_ips = dns_wol.discover_local_ipv4_addresses()

        self.assertEqual(local_ips, {"127.0.0.1", "192.168.1.2", "192.168.1.3"})


if __name__ == "__main__":
    unittest.main()
