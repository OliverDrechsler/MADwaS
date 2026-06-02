import queue
import runpy
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, mock_open, patch

sys.modules.setdefault("yaml", SimpleNamespace(safe_load=lambda *_args, **_kwargs: {}))
sys.modules.setdefault("wakeonlan", SimpleNamespace(send_magic_packet=lambda *_args, **_kwargs: None))
sys.modules.setdefault(
    "scapy.all",
    SimpleNamespace(
        ARP=object(),
        DNS=object(),
        ICMP=object(),
        IP=object(),
        IPv6=object(),
        ICMPv6EchoRequest=object(),
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


class FakeIPv6:
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
    def __init__(self, arp=None, ip=None, ipv6=None, dns=None):
        self._arp = arp
        self._ip = ip
        self._ipv6 = ipv6
        self._dns = dns

    def __contains__(self, layer):
        if layer is dns_wol.ARP:
            return self._arp is not None
        if layer is dns_wol.IP:
            return self._ip is not None
        if layer is dns_wol.IPv6:
            return self._ipv6 is not None
        return False

    def __getitem__(self, layer):
        if layer is dns_wol.ARP:
            return self._arp
        if layer is dns_wol.IP:
            return self._ip
        if layer is dns_wol.IPv6:
            return self._ipv6
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
            blocked_ip={"192.168.1.10", "2001:db8::10"},
            local_ip={"127.0.0.1", "::1", "192.168.1.2", "2001:db8::2"},
            monitoring_by_ip={
                "192.168.1.50": {
                    "ip": "192.168.1.50",
                    "ip_addresses": ("192.168.1.50", "2001:db8::50"),
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "pending_key": "192.168.1.50|2001:db8::50",
                },
                "2001:db8::50": {
                    "ip": "2001:db8::50",
                    "ip_addresses": ("192.168.1.50", "2001:db8::50"),
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "pending_key": "192.168.1.50|2001:db8::50",
                }
            },
            monitoring_by_dns={
                "server.local": {
                    "dns_name": "server.local",
                    "ip": "192.168.1.50",
                    "ip_addresses": ("192.168.1.50", "2001:db8::50"),
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "pending_key": "192.168.1.50|2001:db8::50",
                },
                "server-v6.local": {
                    "dns_name": "server-v6.local",
                    "ip": "192.168.1.50",
                    "ip_addresses": ("192.168.1.50", "2001:db8::50"),
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "pending_key": "192.168.1.50|2001:db8::50",
                }
            },
        )
        dns_wol.work_queue = queue.Queue()
        dns_wol.pending_lock = dns_wol.threading.Lock()
        dns_wol.pending_requests = set()

    @staticmethod
    def _module_attr(name):
        return getattr(dns_wol, name)

    def test_add_object_to_thread_queue_skips_duplicate_ip(self):
        first = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="ARP",
            src_ip="192.168.1.20",
            monitored_ips=("192.168.1.50", "2001:db8::50"),
            pending_key="192.168.1.50|2001:db8::50",
        )
        second = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="DNS Query",
            src_ip="192.168.1.30",
            searched_dns="server.local",
            monitored_ips=("192.168.1.50", "2001:db8::50"),
            pending_key="192.168.1.50|2001:db8::50",
        )

        self._module_attr("__add_object_to_thread_queue")(first)
        self._module_attr("__add_object_to_thread_queue")(second)

        self.assertEqual(dns_wol.work_queue.qsize(), 1)
        queued = dns_wol.work_queue.get_nowait()
        self.assertEqual(queued.src_ip, "192.168.1.20")

    def test_arp_check_ignores_local_requestor(self):
        packet = FakePacket(
            arp=FakeARP(op=1, pdst="192.168.1.50", psrc="192.168.1.2", hwsrc="00:11"),
        )

        self._module_attr("__arp_check")(packet)

        self.assertTrue(dns_wol.work_queue.empty())

    def test_arp_check_enqueues_remote_requestor(self):
        packet = FakePacket(
            arp=FakeARP(op=1, pdst="192.168.1.50", psrc="192.168.1.20", hwsrc="00:11"),
        )

        self._module_attr("__arp_check")(packet)

        queued = dns_wol.work_queue.get_nowait()
        self.assertEqual(queued.request_type, "ARP")
        self.assertEqual(queued.src_ip, "192.168.1.20")
        self.assertEqual(queued.monitored_ips, ("192.168.1.50", "2001:db8::50"))

    def test_dns_query_check_ignores_local_source(self):
        packet = FakePacket(
            ip=FakeIP(src="192.168.1.2"),
            dns=FakeDNS(qname=b"server.local.", qr=0),
        )

        self._module_attr("__dns_query_check")(packet)

        self.assertTrue(dns_wol.work_queue.empty())

    def test_dns_query_check_enqueues_monitored_query(self):
        packet = FakePacket(
            ip=FakeIP(src="192.168.1.30"),
            dns=FakeDNS(qname=b"server.local.", qr=0),
        )

        self._module_attr("__dns_query_check")(packet)

        queued = dns_wol.work_queue.get_nowait()
        self.assertEqual(queued.request_type, "DNS Query")
        self.assertEqual(queued.searched_dns, "server.local")
        self.assertEqual(queued.monitored_ips, ("192.168.1.50", "2001:db8::50"))

    def test_discover_local_ip_addresses_collects_interface_and_hostname_ips(self):
        fake_ifaces = {
            "eth0": SimpleNamespace(ip="192.168.1.2"),
            "lo": SimpleNamespace(ip="127.0.0.1"),
            "ipv6": SimpleNamespace(ip="fe80::1"),
        }
        fake_addrinfo = [
            (None, None, None, None, ("192.168.1.3", 0)),
            (None, None, None, None, ("2001:db8::3", 0, 0, 0)),
            (None, None, None, None, ("192.168.1.2", 0)),
        ]

        with patch.object(dns_wol.conf, "ifaces", fake_ifaces), patch.object(
            dns_wol.socket, "getaddrinfo", return_value=fake_addrinfo
        ):
            local_ips = self._module_attr("__discover_local_ip_addresses")()

        self.assertEqual(
            local_ips,
            {"127.0.0.1", "::1", "192.168.1.2", "192.168.1.3", "fe80::1", "2001:db8::3"},
        )

    def test_discover_local_ipv4_addresses_collects_interface_and_hostname_ips(self):
        self.test_discover_local_ip_addresses_collects_interface_and_hostname_ips()

    def test_dns_query_check_enqueues_monitored_query_for_ipv6_host(self):
        packet = FakePacket(
            ipv6=FakeIPv6(src="2001:db8::30"),
            dns=FakeDNS(qname=b"server-v6.local.", qr=0),
        )

        self._module_attr("__dns_query_check")(packet)

        queued = dns_wol.work_queue.get_nowait()
        self.assertEqual(queued.request_type, "DNS Query")
        self.assertEqual(queued.searched_ip, "192.168.1.50")
        self.assertEqual(queued.src_ip, "2001:db8::30")
        self.assertEqual(queued.monitored_ips, ("192.168.1.50", "2001:db8::50"))

    def test_dns_query_check_deduplicates_monitored_queries_for_ipv4_and_ipv6_of_same_host(self):
        ipv4_packet = FakePacket(
            ip=FakeIP(src="192.168.1.30"),
            dns=FakeDNS(qname=b"server.local.", qr=0),
        )
        ipv6_packet = FakePacket(
            ipv6=FakeIPv6(src="2001:db8::30"),
            dns=FakeDNS(qname=b"server-v6.local.", qr=0),
        )

        self._module_attr("__dns_query_check")(ipv4_packet)
        self._module_attr("__dns_query_check")(ipv6_packet)

        self.assertEqual(dns_wol.work_queue.qsize(), 1)
        queued = dns_wol.work_queue.get_nowait()
        self.assertEqual(queued.searched_ip, "192.168.1.50")
        self.assertEqual(queued.src_ip, "192.168.1.30")
        self.assertEqual(queued.monitored_ips, ("192.168.1.50", "2001:db8::50"))

    def test_configuration_normalizes_ipv4_and_ipv6_monitoring_ips_for_one_host(self):
        raw_config = {
            "monitoring": [
                {
                    "dns_name": "server-v6.local.",
                    "ip": "192.168.1.50",
                    "ipv6": "2001:0db8:0000:0000:0000:0000:0000:0050",
                    "mac": "aa:bb:cc:dd:ee:ff",
                }
            ]
        }

        with patch.object(
            dns_wol.Configuration,
            "_Configuration__read_config",
            return_value=raw_config,
        ), patch.object(
            dns_wol, "__discover_local_ip_addresses", return_value={"::1"}
        ):
            config = dns_wol.Configuration()

        self.assertIn("192.168.1.50", config.monitoring_by_ip)
        self.assertIn("2001:db8::50", config.monitoring_by_ip)
        self.assertEqual(
            config.monitoring_by_dns["server-v6.local"]["ip_addresses"],
            ("192.168.1.50", "2001:db8::50"),
        )

    def test_configuration_skips_invalid_monitoring_entries_and_normalizes_blocked_ips(self):
        raw_config = {
            "blocked_ip": ["192.168.1.10", "invalid", "2001:db8::10"],
            "monitoring": [
                {"dns_name": "invalid.local", "ip": "not-an-ip", "mac": "aa:bb"},
                {"dns_name": "missing-mac.local", "ip": "192.168.1.50"},
                {
                    "dns_name": "multi.local.",
                    "ipv4": "192.168.1.51",
                    "ipv6": "2001:db8::51",
                    "ips": ["192.168.1.51", "2001:db8::52"],
                    "mac": "aa:bb:cc:dd:ee:ff",
                },
            ],
        }

        with patch.object(
            dns_wol.Configuration,
            "_Configuration__read_config",
            return_value=raw_config,
        ), patch.object(
            dns_wol, "__discover_local_ip_addresses", return_value={"::1"}
        ), patch.object(dns_wol, "logger") as fake_logger:
            config = dns_wol.Configuration()

        self.assertEqual(config.blocked_ip, {"192.168.1.10", "2001:db8::10"})
        self.assertEqual(
            config.monitoring_by_dns["multi.local"]["ip_addresses"],
            ("192.168.1.51", "2001:db8::51", "2001:db8::52"),
        )
        self.assertEqual(fake_logger.warning.call_count, 2)

    def test_read_config_returns_yaml_content(self):
        raw_config = {"monitoring": [{"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff"}]}

        with patch("builtins.open", mock_open(read_data="ignored")), patch.object(
            dns_wol.yaml, "safe_load", return_value=raw_config
        ):
            config = dns_wol.Configuration._Configuration__read_config("dummy.yaml")

        self.assertEqual(config, raw_config)

    def test_duplicate_requests_for_ipv4_and_ipv6_of_same_host_are_deduplicated(self):
        arp_request = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="ARP",
            src_ip="192.168.1.20",
            monitored_ips=("192.168.1.50", "2001:db8::50"),
            pending_key="192.168.1.50|2001:db8::50",
        )
        dns_request = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="DNS Query",
            src_ip="2001:db8::30",
            searched_dns="server-v6.local",
            monitored_ips=("192.168.1.50", "2001:db8::50"),
            pending_key="192.168.1.50|2001:db8::50",
        )

        self._module_attr("__add_object_to_thread_queue")(arp_request)
        self._module_attr("__add_object_to_thread_queue")(dns_request)

        self.assertEqual(dns_wol.work_queue.qsize(), 1)
        queued = dns_wol.work_queue.get_nowait()
        self.assertEqual(queued.request_type, "ARP")

    def test_sendmail_returns_disabled_when_feature_is_off(self):
        result = dns_wol.sendmail("subject", "from@example.org", "to@example.org")
        self.assertEqual(result, (False, "sendmail disabled"))

    def test_sendmail_sends_message_via_local_smtp(self):
        dns_wol.config.enable_mail = True
        fake_smtp = MagicMock()
        fake_smtp.__enter__.return_value = fake_smtp
        fake_smtp.__exit__.return_value = False

        with patch.object(dns_wol.smtplib, "SMTP", return_value=fake_smtp):
            result = dns_wol.sendmail("subject", "from@example.org", "to@example.org")

        self.assertEqual(result, (True, (221, b"Bye")))
        fake_smtp.send_message.assert_called_once()

    def test_sendmail_returns_failure_when_smtp_raises_oserror(self):
        dns_wol.config.enable_mail = True

        with patch.object(dns_wol.smtplib, "SMTP", side_effect=OSError), patch.object(
            dns_wol, "logger"
        ) as fake_logger:
            result = dns_wol.sendmail("subject", "from@example.org", "to@example.org")

        self.assertEqual(result, (False, "smtp failed"))
        fake_logger.exception.assert_called_once()

    def test_normalize_ip_address_rejects_invalid_value(self):
        self.assertIsNone(self._module_attr("__normalize_ip_address")("not-an-ip"))

    def test_discover_local_ip_addresses_ignores_invalid_iface_and_getaddrinfo_failure(self):
        fake_ifaces = {
            "eth0": SimpleNamespace(ip=None),
            "bad": SimpleNamespace(ip="not-an-ip"),
        }

        with patch.object(dns_wol.conf, "ifaces", fake_ifaces), patch.object(
            dns_wol.socket, "getaddrinfo", side_effect=OSError
        ):
            local_ips = self._module_attr("__discover_local_ip_addresses")()

        self.assertEqual(local_ips, {"127.0.0.1", "::1"})

    def test_discover_local_ip_addresses_ignores_invalid_hostname_results(self):
        fake_ifaces = {}
        fake_addrinfo = [
            (None, None, None, None, ("not-an-ip", 0)),
            (None, None, None, None, ("192.168.1.3", 0)),
        ]

        with patch.object(dns_wol.conf, "ifaces", fake_ifaces), patch.object(
            dns_wol.socket, "getaddrinfo", return_value=fake_addrinfo
        ):
            local_ips = self._module_attr("__discover_local_ip_addresses")()

        self.assertEqual(local_ips, {"127.0.0.1", "::1", "192.168.1.3"})

    def test_icmp_check_returns_false_when_host_does_not_answer(self):
        fake_ip_packet = MagicMock()
        with patch.object(dns_wol, "IP", return_value=fake_ip_packet), patch.object(
            dns_wol, "ICMP", return_value=MagicMock()
        ), patch.object(dns_wol, "sr1", return_value=None):
            result = self._module_attr("__icmp_check")("192.168.1.50")

        self.assertFalse(result)

    def test_icmp_check_uses_ipv6_echo_request(self):
        fake_ipv6_packet = MagicMock()
        fake_icmpv6 = MagicMock()
        with patch.object(dns_wol, "IPv6", return_value=fake_ipv6_packet) as ipv6_ctor, patch.object(
            dns_wol, "ICMPv6EchoRequest", return_value=fake_icmpv6
        ), patch.object(
            dns_wol, "sr1", return_value=object()
        ):
            result = self._module_attr("__icmp_check")("2001:db8::50")

        self.assertTrue(result)
        ipv6_ctor.assert_called_once_with(dst="2001:db8::50")

    def test_host_is_reachable_returns_true_when_any_ip_answers(self):
        with patch.object(dns_wol, "__icmp_check", side_effect=[False, True]) as icmp_check:
            result = self._module_attr("__host_is_reachable")(("192.168.1.50", "2001:db8::50"))

        self.assertTrue(result)
        self.assertEqual(icmp_check.call_count, 2)

    def test_host_is_reachable_returns_false_when_no_ip_answers(self):
        with patch.object(dns_wol, "__icmp_check", side_effect=[False, False]) as icmp_check:
            result = self._module_attr("__host_is_reachable")(("192.168.1.50", "2001:db8::50"))

        self.assertFalse(result)
        self.assertEqual(icmp_check.call_count, 2)

    def test_wakeup_monitored_host_returns_false_when_host_is_already_reachable(self):
        request = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="DNS Query",
            src_ip="192.168.1.20",
            monitored_ips=("192.168.1.50", "2001:db8::50"),
            pending_key="192.168.1.50|2001:db8::50",
        )
        dns_wol.pending_requests.add(request.pending_key)

        with patch.object(dns_wol, "__host_is_reachable", return_value=True), patch.object(
            dns_wol, "send_magic_packet"
        ) as send_magic_packet:
            result = dns_wol.wakeup_monitored_host(request)

        self.assertFalse(result)
        self.assertNotIn(request.pending_key, dns_wol.pending_requests)
        send_magic_packet.assert_not_called()

    def test_wakeup_monitored_host_sends_magic_packet_and_mail_when_host_is_down(self):
        request = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="DNS Query",
            src_ip="192.168.1.20",
            monitored_ips=("192.168.1.50", "2001:db8::50"),
            pending_key="192.168.1.50|2001:db8::50",
        )
        dns_wol.pending_requests.add(request.pending_key)

        with patch.object(dns_wol, "__host_is_reachable", return_value=False), patch.object(
            dns_wol, "send_magic_packet"
        ) as send_magic_packet, patch.object(
            dns_wol, "sendmail", return_value=(True, (221, b"Bye"))
        ) as sendmail, patch.object(
            dns_wol.time, "sleep"
        ) as sleep:
            result = dns_wol.wakeup_monitored_host(request)

        self.assertTrue(result)
        send_magic_packet.assert_called_once_with("aa:bb:cc:dd:ee:ff")
        sendmail.assert_called_once()
        sleep.assert_called_once_with(0)
        self.assertNotIn(request.pending_key, dns_wol.pending_requests)

    def test_wakeup_monitored_host_handles_exception_and_clears_pending_request(self):
        request = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="DNS Query",
            src_ip="192.168.1.20",
            pending_key="192.168.1.50|2001:db8::50",
        )
        dns_wol.pending_requests.add(request.pending_key)

        with patch.object(dns_wol, "__host_is_reachable", side_effect=RuntimeError), patch.object(
            dns_wol, "logger"
        ) as fake_logger:
            result = dns_wol.wakeup_monitored_host(request)

        self.assertFalse(result)
        self.assertNotIn(request.pending_key, dns_wol.pending_requests)
        fake_logger.exception.assert_called_once()

    def test_arp_check_ignores_non_request_and_invalid_addresses(self):
        non_request = FakePacket(arp=FakeARP(op=2, pdst="192.168.1.50", psrc="192.168.1.20"))
        invalid = FakePacket(arp=FakeARP(op=1, pdst="invalid", psrc="192.168.1.20"))

        self._module_attr("__arp_check")(non_request)
        self._module_attr("__arp_check")(invalid)

        self.assertTrue(dns_wol.work_queue.empty())

    def test_arp_check_ignores_unmonitored_target(self):
        packet = FakePacket(
            arp=FakeARP(op=1, pdst="192.168.1.99", psrc="192.168.1.20", hwsrc="00:11"),
        )

        self._module_attr("__arp_check")(packet)

        self.assertTrue(dns_wol.work_queue.empty())

    def test_arp_check_ignores_blocked_and_self_requestor(self):
        blocked = FakePacket(
            arp=FakeARP(op=1, pdst="192.168.1.50", psrc="192.168.1.10", hwsrc="00:11"),
        )
        self_request = FakePacket(
            arp=FakeARP(op=1, pdst="192.168.1.50", psrc="2001:db8::50", hwsrc="00:11"),
        )

        self._module_attr("__arp_check")(blocked)
        self._module_attr("__arp_check")(self_request)

        self.assertTrue(dns_wol.work_queue.empty())

    def test_dns_query_check_ignores_missing_question_unknown_name_and_missing_ip_layer(self):
        missing_question = FakePacket(ip=FakeIP(src="192.168.1.20"), dns=FakeDNS(qname=None, qr=0))
        unknown_name = FakePacket(ip=FakeIP(src="192.168.1.20"), dns=FakeDNS(qname=b"unknown.local.", qr=0))
        no_ip_layer = FakePacket(dns=FakeDNS(qname=b"server.local.", qr=0))

        self._module_attr("__dns_query_check")(missing_question)
        self._module_attr("__dns_query_check")(unknown_name)
        self._module_attr("__dns_query_check")(no_ip_layer)

        self.assertTrue(dns_wol.work_queue.empty())

    def test_dns_query_check_ignores_blocked_and_self_source(self):
        blocked = FakePacket(ip=FakeIP(src="192.168.1.10"), dns=FakeDNS(qname=b"server.local.", qr=0))
        self_source = FakePacket(
            ipv6=FakeIPv6(src="2001:db8::50"),
            dns=FakeDNS(qname=b"server-v6.local.", qr=0),
        )

        self._module_attr("__dns_query_check")(blocked)
        self._module_attr("__dns_query_check")(self_source)

        self.assertTrue(dns_wol.work_queue.empty())

    def test_dns_query_check_logs_exception_for_broken_packet(self):
        broken_packet = SimpleNamespace(getlayer=MagicMock(side_effect=RuntimeError("boom")))

        with patch.object(dns_wol, "logger") as fake_logger:
            self._module_attr("__dns_query_check")(broken_packet)

        fake_logger.exception.assert_called_once()

    def test_get_packet_source_ip_returns_none_without_ip_layers(self):
        packet = FakePacket()
        self.assertIsNone(self._module_attr("__get_packet_source_ip")(packet))

    def test_sniff_arp_and_dns_dispatches_arp_and_dns(self):
        packet = FakePacket(
            arp=FakeARP(op=1, pdst="192.168.1.50", psrc="192.168.1.20"),
            ip=FakeIP(src="192.168.1.20"),
            dns=FakeDNS(qname=b"server.local.", qr=0),
        )

        with patch.object(dns_wol, "__arp_check") as arp_check, patch.object(
            dns_wol, "__dns_query_check"
        ) as dns_query_check:
            self._module_attr("__sniff_arp_and_dns")(packet)

        arp_check.assert_called_once_with(packet)
        dns_query_check.assert_called_once_with(packet)

    def test_sniff_arp_and_dns_ignores_dns_responses(self):
        packet = FakePacket(ip=FakeIP(src="192.168.1.20"), dns=FakeDNS(qname=b"server.local.", qr=1))

        with patch.object(dns_wol, "__dns_query_check") as dns_query_check:
            self._module_attr("__sniff_arp_and_dns")(packet)

        dns_query_check.assert_not_called()

    def test_load_config_sets_global_configuration(self):
        fake_config = object()
        with patch.object(dns_wol, "Configuration", return_value=fake_config):
            self._module_attr("__load_config")()

        self.assertIs(dns_wol.config, fake_config)

    def test_is_log_path_writable_uses_existing_file_permissions(self):
        with patch.object(dns_wol.Path, "exists", return_value=True), patch.object(
            dns_wol.os, "access", return_value=True
        ) as access:
            self.assertTrue(self._module_attr("__is_log_path_writable")(dns_wol.SYSTEM_LOG_FILE_PATHS[0]))

        access.assert_called_once_with(dns_wol.SYSTEM_LOG_FILE_PATHS[0], dns_wol.os.W_OK)

    def test_resolve_log_file_path_prefers_system_log_path(self):
        with patch.object(dns_wol, "__is_log_path_writable", side_effect=[True]):
            log_file_path = self._module_attr("__resolve_log_file_path")()

        self.assertEqual(log_file_path, dns_wol.SYSTEM_LOG_FILE_PATHS[0])

    def test_resolve_log_file_path_falls_back_to_repo_log_path(self):
        with patch.object(dns_wol, "__is_log_path_writable", return_value=False):
            log_file_path = self._module_attr("__resolve_log_file_path")()

        self.assertEqual(log_file_path, dns_wol.FALLBACK_LOG_FILE_PATH)

    def test_is_log_path_writable_checks_parent_directory_for_new_file(self):
        fake_path = SimpleNamespace(
            exists=lambda: False,
            parent=SimpleNamespace(is_dir=lambda: True),
        )

        with patch.object(dns_wol.os, "access", return_value=True) as access:
            result = self._module_attr("__is_log_path_writable")(fake_path)

        self.assertTrue(result)
        access.assert_called_once_with(fake_path.parent, dns_wol.os.W_OK)

    def test_load_log_config_resolves_preferred_log_path(self):
        raw_log_config = {
            "root": {"level": "INFO"},
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "level": "INFO",
                },
                "rotating_file_handler": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "level": "INFO",
                    "filename": "dns_wol.log",
                }
            },
            "loggers": {
                "sampleLogger": {
                    "level": "INFO",
                }
            }
        }

        with patch("builtins.open", mock_open(read_data="ignored")), patch.object(
            dns_wol.yaml, "safe_load", return_value=raw_log_config
        ), patch.object(
            dns_wol, "__resolve_log_file_path", return_value=dns_wol.SYSTEM_LOG_FILE_PATHS[0]
        ):
            log_config = dns_wol.load_log_config()

        self.assertEqual(
            log_config["handlers"]["rotating_file_handler"]["filename"],
            str(dns_wol.SYSTEM_LOG_FILE_PATHS[0]),
        )
        self.assertFalse(log_config["disable_existing_loggers"])

    def test_load_log_config_force_debug_overrides_levels(self):
        raw_log_config = {
            "root": {"level": "INFO"},
            "handlers": {
                "console": {"level": "INFO"},
                "rotating_file_handler": {"level": "WARNING", "filename": "dns_wol.log"},
            },
            "loggers": {
                "sampleLogger": {"level": "ERROR"},
            },
        }

        with patch("builtins.open", mock_open(read_data="ignored")), patch.object(
            dns_wol.yaml, "safe_load", return_value=raw_log_config
        ):
            log_config = dns_wol.load_log_config(force_debug=True)

        self.assertEqual(log_config["root"]["level"], "DEBUG")
        self.assertEqual(log_config["handlers"]["console"]["level"], "DEBUG")
        self.assertEqual(log_config["handlers"]["rotating_file_handler"]["level"], "DEBUG")
        self.assertEqual(log_config["loggers"]["sampleLogger"]["level"], "DEBUG")

    def test_load_log_config_without_rotating_handler_keeps_handlers_unchanged(self):
        raw_log_config = {"handlers": {"console": {"level": "INFO"}}}

        with patch("builtins.open", mock_open(read_data="ignored")), patch.object(
            dns_wol.yaml, "safe_load", return_value=raw_log_config
        ):
            log_config = dns_wol.load_log_config()

        self.assertNotIn("rotating_file_handler", log_config["handlers"])

    def test_parse_args_debug_flag(self):
        args = dns_wol.parse_args(["--debug"])
        self.assertTrue(args.debug)

    def test_parse_args_default_debug_disabled(self):
        args = dns_wol.parse_args([])
        self.assertFalse(args.debug)

    def test_report_fatal_exception_prints_traceback_to_stderr(self):
        fake_logger = MagicMock()
        stderr = SimpleNamespace(write=lambda *_args, **_kwargs: None, flush=lambda: None)

        with patch.object(dns_wol, "logger", fake_logger), patch.object(
            dns_wol.traceback, "print_exc"
        ) as print_exc:
            try:
                raise RuntimeError("boom")
            except RuntimeError:
                with patch.object(dns_wol.sys, "stderr", stderr):
                    self._module_attr("__report_fatal_exception")(dns_wol.EXCEPTION_MESSAGE)

        fake_logger.exception.assert_called_once_with(dns_wol.EXCEPTION_MESSAGE, exc_info=True)
        print_exc.assert_called_once_with(file=stderr)

    def test_clear_pending_request_removes_entry(self):
        dns_wol.pending_requests.add("host-key")
        self._module_attr("__clear_pending_request")("host-key")
        self.assertNotIn("host-key", dns_wol.pending_requests)

    def test_check_thread_queue_processes_item_and_marks_done(self):
        request = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="ARP",
            src_ip="192.168.1.20",
        )
        fake_queue = MagicMock()
        fake_queue.get.side_effect = [request, KeyboardInterrupt]
        dns_wol.work_queue = fake_queue

        with patch.object(dns_wol, "wakeup_monitored_host") as wakeup_monitored_host:
            with self.assertRaises(KeyboardInterrupt):
                self._module_attr("__check_thread_queue")()

        wakeup_monitored_host.assert_called_once_with(request)
        fake_queue.task_done.assert_called_once_with()

    def test_get_pending_request_key_prefers_pending_key(self):
        request = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="ARP",
            src_ip="192.168.1.20",
            pending_key="host-key",
        )

        self.assertEqual(self._module_attr("__get_pending_request_key")(request), "host-key")

    def test_get_pending_request_key_falls_back_to_searched_ip(self):
        request = dns_wol.WakeupRequest(
            searched_ip="192.168.1.50",
            searched_mac="aa:bb:cc:dd:ee:ff",
            request_type="ARP",
            src_ip="192.168.1.20",
        )

        self.assertEqual(self._module_attr("__get_pending_request_key")(request), "192.168.1.50")

    def test_main_exits_cleanly_on_keyboard_interrupt(self):
        scapy_module = sys.modules["scapy.all"]
        fake_thread = MagicMock()

        with patch("builtins.open", mock_open(read_data="ignored")), patch.object(
            sys.modules["yaml"],
            "safe_load",
            side_effect=[{"handlers": {}, "root": {}}, {"monitoring": [], "blocked_ip": []}],
        ), patch.object(
            scapy_module, "sniff", side_effect=KeyboardInterrupt
        ), patch.object(
            dns_wol.logging.config, "dictConfig"
        ), patch.object(
            dns_wol.threading, "Thread", return_value=fake_thread
        ), patch.object(
            sys, "argv", ["dns_wol.py"]
        ), patch.object(
            sys, "exit", side_effect=SystemExit(1)
        ):
            with self.assertRaises(SystemExit) as exit_info:
                runpy.run_module("dns_wol", run_name="__main__")

        self.assertEqual(exit_info.exception.code, 1)
        fake_thread.start.assert_called_once_with()

    def test_main_reports_fatal_exception_and_exits_on_sniff_error(self):
        scapy_module = sys.modules["scapy.all"]
        fake_thread = MagicMock()

        with patch("builtins.open", mock_open(read_data="ignored")), patch.object(
            sys.modules["yaml"],
            "safe_load",
            side_effect=[{"handlers": {}, "root": {}}, {"monitoring": [], "blocked_ip": []}],
        ), patch.object(
            scapy_module, "sniff", side_effect=RuntimeError("boom")
        ), patch.object(
            dns_wol.logging.config, "dictConfig"
        ), patch.object(
            dns_wol.threading, "Thread", return_value=fake_thread
        ), patch.object(
            dns_wol.traceback, "print_exc"
        ), patch.object(
            sys, "argv", ["dns_wol.py"]
        ), patch.object(
            sys, "exit", side_effect=SystemExit(1)
        ):
            with self.assertRaises(SystemExit) as exit_info:
                runpy.run_module("dns_wol", run_name="__main__")

        self.assertEqual(exit_info.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
