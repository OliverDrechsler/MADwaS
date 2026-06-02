import queue
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

    def test_is_log_path_writable_uses_existing_file_permissions(self):
        with patch.object(dns_wol.Path, "exists", return_value=True), patch.object(
            dns_wol.os, "access", return_value=True
        ) as access:
            self.assertTrue(dns_wol.is_log_path_writable(dns_wol.SYSTEM_LOG_FILE_PATHS[0]))

        access.assert_called_once_with(dns_wol.SYSTEM_LOG_FILE_PATHS[0], dns_wol.os.W_OK)

    def test_resolve_log_file_path_prefers_system_log_path(self):
        with patch.object(dns_wol, "is_log_path_writable", side_effect=[True]):
            log_file_path = dns_wol.resolve_log_file_path()

        self.assertEqual(log_file_path, dns_wol.SYSTEM_LOG_FILE_PATHS[0])

    def test_resolve_log_file_path_falls_back_to_repo_log_path(self):
        with patch.object(dns_wol, "is_log_path_writable", return_value=False):
            log_file_path = dns_wol.resolve_log_file_path()

        self.assertEqual(log_file_path, dns_wol.FALLBACK_LOG_FILE_PATH)

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
            dns_wol, "resolve_log_file_path", return_value=dns_wol.SYSTEM_LOG_FILE_PATHS[0]
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
                    dns_wol.report_fatal_exception(dns_wol.EXCEPTION_MESSAGE)

        fake_logger.exception.assert_called_once_with(dns_wol.EXCEPTION_MESSAGE, exc_info=True)
        print_exc.assert_called_once_with(file=stderr)


if __name__ == "__main__":
    unittest.main()
