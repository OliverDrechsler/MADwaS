#!/usr/bin/env python3

import argparse
import ipaddress
import logging
import logging.config
import os
import queue
import smtplib
import socket
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

import yaml
from scapy.all import ARP, DNS, ICMP, IP, IPv6, ICMPv6EchoRequest, conf, sniff, sr1
from wakeonlan import send_magic_packet


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.sniff_promisc = True

EXCEPTION_MESSAGE = "Exception occurred"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"
CONFIG_TEMPLATE_PATH = BASE_DIR / "config_template.yaml"
LOG_CONFIG_PATH = BASE_DIR / "log_config.yaml"
FALLBACK_LOG_FILE_PATH = BASE_DIR / "dns_wol.log"
SYSTEM_LOG_FILE_PATHS = (Path("/var/log/dns_wol.log"),)

logger = logging.getLogger(__name__)
config = None
work_queue = None
pending_lock = threading.Lock()
pending_requests = set()
WAKEUP_REQUEST_DATACLASS_KWARGS = {"frozen": True}
if sys.version_info >= (3, 10):
    WAKEUP_REQUEST_DATACLASS_KWARGS["slots"] = True


@dataclass(**WAKEUP_REQUEST_DATACLASS_KWARGS)
class WakeupRequest:
    searched_ip: str
    searched_mac: str
    request_type: str
    src_ip: str
    searched_dns: Optional[str] = None
    monitored_ips: tuple[str, ...] = ()
    pending_key: Optional[str] = None


class Configuration:
    """Read the YAML config and prepare lookup tables."""

    def __init__(self):
        self.config_file = CONFIG_PATH if CONFIG_PATH.is_file() else CONFIG_TEMPLATE_PATH
        logger.debug("Using config file %s", self.config_file)
        self.config = self.__read_config(self.config_file)
        self.blocked_ip = {
            normalized_ip
            for normalized_ip in (
                globals()["__normalize_ip_address"](ip_address)
                for ip_address in self.config.get("blocked_ip", [])
            )
            if normalized_ip
        }
        self.monitoring = self.config.get("monitoring", [])
        self.from_mail = self.config.get("from_mail", "")
        self.to_mail = self.config.get("to_mail", "")
        self.enable_mail = bool(self.config.get("enable_mail", False))
        self.wait_time = int(self.config.get("wait_time", 45))
        self.local_ip = globals()["__discover_local_ip_addresses"]()
        self.monitoring_by_ip = {}
        self.monitoring_by_dns = {}
        self._build_lookup_tables()

    @staticmethod
    def __read_config(config_file):
        with open(file=config_file, mode="r", encoding="utf-8") as file:
            config = yaml.safe_load(file) or {}
        logger.debug("Loaded config: %s", config)
        return config

    def _build_lookup_tables(self):
        for entry in self.monitoring:
            ip_addresses = self._extract_ip_addresses(entry)
            dns_name = str(entry.get("dns_name", "")).lower().rstrip(".")
            if not ip_addresses or not entry.get("mac"):
                logger.warning("Skipping invalid monitoring entry: %s", entry)
                continue

            normalized_entry = dict(entry)
            normalized_entry["ip_addresses"] = ip_addresses
            normalized_entry["ip"] = ip_addresses[0]
            normalized_entry["pending_key"] = "|".join(ip_addresses)
            for ip_address in ip_addresses:
                self.monitoring_by_ip[ip_address] = normalized_entry
            if dns_name:
                normalized_entry["dns_name"] = dns_name
                self.monitoring_by_dns[dns_name] = normalized_entry

    @staticmethod
    def _extract_ip_addresses(entry):
        ip_addresses = []
        for field_name in ("ip", "ipv4", "ipv6"):
            normalized_ip = globals()["__normalize_ip_address"](entry.get(field_name))
            if normalized_ip and normalized_ip not in ip_addresses:
                ip_addresses.append(normalized_ip)

        for ip_value in entry.get("ips", []):
            normalized_ip = globals()["__normalize_ip_address"](ip_value)
            if normalized_ip and normalized_ip not in ip_addresses:
                ip_addresses.append(normalized_ip)

        return tuple(ip_addresses)


def sendmail(message_text, sender, recipient):
    """Send a message via the local SMTP daemon."""
    if not config.enable_mail:
        return False, "sendmail disabled"

    message = EmailMessage()
    message["From"] = f"<{sender}>"
    message["To"] = f"<{recipient}>"
    message["Subject"] = message_text
    message.set_content(message_text)

    try:
        with smtplib.SMTP("localhost") as smtp:
            smtp.send_message(message)
            logger.debug("sendmail result code 221")
            return True, (221, b"Bye")
    except OSError:
        logger.exception("Sending mail failed")
        return False, "smtp failed"


def __normalize_ip_address(value):
    """Return a normalized IP string or None for invalid values."""
    if value in (None, ""):
        return None

    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def __discover_local_ip_addresses():
    """Collect IPv4 and IPv6 addresses assigned to the local host."""
    local_ips = {"127.0.0.1", "::1"}
    for iface in conf.ifaces.values():
        iface_ip = getattr(iface, "ip", None)
        normalized_ip = __normalize_ip_address(iface_ip)
        if normalized_ip:
            local_ips.add(normalized_ip)

    try:
        host_entries = socket.getaddrinfo(socket.gethostname(), None, type=socket.SOCK_DGRAM)
        for entry in host_entries:
            ip_address = entry[4][0]
            normalized_ip = __normalize_ip_address(ip_address)
            if normalized_ip:
                local_ips.add(normalized_ip)
    except OSError:
        logger.debug("Unable to resolve local host addresses via getaddrinfo")

    logger.info("Ignoring packets originating from local IPs: %s", sorted(local_ips))
    return local_ips


def __icmp_check(ipaddress, attempts=2, timeout=1):
    """Send ICMP echo requests to check if an IP is online."""
    ip_obj = __ipaddress_module(ipaddress)
    logger.info("ICMP checking if %s is alive", ipaddress)
    for attempt in range(1, attempts + 1):
        if ip_obj.version == 6:
            packet = IPv6(dst=ipaddress) / ICMPv6EchoRequest()
        else:
            packet = IP(dst=ipaddress) / ICMP()
        response = sr1(packet, timeout=timeout, verbose=0)
        logger.debug("icmp attempt %s response=%s", attempt, response)
        if response is not None:
            logger.info("IP %s is alive", ipaddress)
            return True
    logger.info("ICMP to IP %s is not answering", ipaddress)
    return False


def __host_is_reachable(ip_addresses, attempts=2, timeout=1):
    """Return True when any configured address for the host responds."""
    for ip_address in ip_addresses:
        if __icmp_check(ip_address, attempts=attempts, timeout=timeout):
            return True
    return False


def wakeup_monitored_host(wakeup_request):
    """Wake the monitored host if it does not answer ICMP."""
    try:
        asked_for = wakeup_request.searched_dns or wakeup_request.searched_ip
        logger.info(
            "%s request detected - %s asks for %s",
            wakeup_request.request_type,
            wakeup_request.src_ip,
            asked_for,
        )

        monitored_ips = wakeup_request.monitored_ips or (wakeup_request.searched_ip,)
        if __host_is_reachable(monitored_ips):
            logger.info("No wake up needed - host %s is alive", ", ".join(monitored_ips))
            return False

        message = (
            f"WoL WakeUp - {wakeup_request.request_type} Request detected - "
            f"IP {wakeup_request.src_ip} asks for {asked_for}"
        )
        logger.info(message)
        logger.debug(
            "Sending WoL packet to MAC %s of IP %s",
            wakeup_request.searched_mac,
            wakeup_request.searched_ip,
        )
        send_magic_packet(wakeup_request.searched_mac)
        sendmail(message, config.from_mail, config.to_mail)
        logger.debug("Waiting %s seconds for host spin-up", config.wait_time)
        time.sleep(config.wait_time)
        return True
    except Exception:
        logger.exception(EXCEPTION_MESSAGE, exc_info=True)
        return False
    finally:
        __clear_pending_request(__get_pending_request_key(wakeup_request))


def __arp_check(pkt):
    """Check if an ARP request targets a monitored host."""
    logger.debug("check arp packet %s == 1", pkt[ARP].op)
    if pkt[ARP].op != 1:
        return

    searched_arp_ip = __normalize_ip_address(pkt[ARP].pdst)
    requestor_arp_ip = __normalize_ip_address(pkt[ARP].psrc)
    if not searched_arp_ip or not requestor_arp_ip:
        return
    logger.debug(
        "hwsrc %s psrc %s pdst %s",
        pkt[ARP].hwsrc,
        requestor_arp_ip,
        searched_arp_ip,
    )

    monitored_entry = config.monitoring_by_ip.get(searched_arp_ip)
    if not monitored_entry:
        return

    logger.debug("monitored %s == searched %s", monitored_entry["ip"], searched_arp_ip)
    if requestor_arp_ip in config.local_ip:
        logger.debug("Ignoring locally generated ARP request from %s", requestor_arp_ip)
        return

    if requestor_arp_ip in config.blocked_ip or requestor_arp_ip in monitored_entry["ip_addresses"]:
        return

    logger.debug("ARP request accepted from %s", requestor_arp_ip)
    __add_object_to_thread_queue(
        WakeupRequest(
            searched_ip=searched_arp_ip,
            searched_mac=monitored_entry["mac"],
            request_type="ARP",
            src_ip=requestor_arp_ip,
            monitored_ips=monitored_entry["ip_addresses"],
            pending_key=monitored_entry["pending_key"],
        )
    )


def __dns_query_check(pkt):
    """Check if a DNS query targets a monitored host."""
    try:
        dns_layer = pkt.getlayer(DNS)
        if dns_layer.qd is None or dns_layer.qd.qname is None:
            return

        dns_name = dns_layer.qd.qname.decode("ascii", errors="ignore").lower().rstrip(".")
        logger.debug("check dns query %s", dns_name)
        monitored_entry = config.monitoring_by_dns.get(dns_name)
        if not monitored_entry:
            return

        logger.debug("monitored %s == searched %s", monitored_entry["dns_name"], dns_name)
        ip_src = __get_packet_source_ip(pkt)
        if not ip_src:
            logger.debug("Skipping DNS request without IP source layer")
            return
        if ip_src in config.local_ip:
            logger.debug("Ignoring locally generated DNS request from %s", ip_src)
            return

        if ip_src in config.blocked_ip or ip_src in monitored_entry["ip_addresses"]:
            return

        logger.debug("DNS request accepted from %s", ip_src)
        __add_object_to_thread_queue(
            WakeupRequest(
                searched_ip=monitored_entry["ip"],
                searched_mac=monitored_entry["mac"],
                request_type="DNS Query",
                src_ip=ip_src,
                searched_dns=dns_name,
                monitored_ips=monitored_entry["ip_addresses"],
                pending_key=monitored_entry["pending_key"],
            )
        )
    except Exception:
        logger.exception(EXCEPTION_MESSAGE, exc_info=True)


def __ipaddress_module(value):
    """Parse and return an ipaddress object."""
    return ipaddress.ip_address(value)


def __get_packet_source_ip(pkt):
    """Return the source IP for IPv4 or IPv6 packets."""
    if IP in pkt:
        return __normalize_ip_address(pkt[IP].src)
    if IPv6 in pkt:
        return __normalize_ip_address(pkt[IPv6].src)
    return None


def __sniff_arp_and_dns(pkt):
    """Pre-check sniffed ethernet packets for ARP or DNS queries."""
    logger.debug("sniffed packet to check: %s", pkt.summary())
    if ARP in pkt:
        logger.debug("ARP packet detected")
        __arp_check(pkt)

    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        logger.debug("DNS packet detected")
        __dns_query_check(pkt)


def __load_config():
    global config
    config = Configuration()


def parse_args(argv=None):
    """Parse CLI options."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--debug",
        action="store_true",
        help="force debug logging regardless of log_config.yaml",
    )
    return parser.parse_args(argv)


def __is_log_path_writable(log_file_path):
    """Return True when the log file path can be opened by the current user."""
    if log_file_path.exists():
        return os.access(log_file_path, os.W_OK)

    parent_dir = log_file_path.parent
    return parent_dir.is_dir() and os.access(parent_dir, os.W_OK)


def __resolve_log_file_path():
    """Prefer a system log file path and fall back to the project directory."""
    for log_file_path in SYSTEM_LOG_FILE_PATHS:
        if __is_log_path_writable(log_file_path):
            return log_file_path
    return FALLBACK_LOG_FILE_PATH


def load_log_config(force_debug=False):
    """Load logging config and pin the log file to the project directory."""
    with open(file=LOG_CONFIG_PATH, mode="r", encoding="utf-8") as file:
        log_config = yaml.safe_load(file) or {}

    # Keep the module logger active when the script is executed directly.
    log_config.setdefault("disable_existing_loggers", False)

    handlers = log_config.get("handlers", {})
    rotating_handler = handlers.get("rotating_file_handler")
    if rotating_handler is not None:
        rotating_handler["filename"] = str(__resolve_log_file_path())

    if force_debug:
        log_config["root"] = {**log_config.get("root", {}), "level": "DEBUG"}
        for handler_config in handlers.values():
            handler_config["level"] = "DEBUG"
        for logger_config in log_config.get("loggers", {}).values():
            logger_config["level"] = "DEBUG"

    return log_config


def __report_fatal_exception(message):
    """Log a fatal exception and mirror it to stderr for interactive runs."""
    logger.exception(message, exc_info=True)
    traceback.print_exc(file=sys.stderr)


def __clear_pending_request(ip_address):
    with pending_lock:
        pending_requests.discard(ip_address)


def __check_thread_queue():
    logger.info("starting endless check queue loop")
    while True:
        wakeup_request = work_queue.get()
        try:
            wakeup_monitored_host(wakeup_request)
        finally:
            work_queue.task_done()


def __add_object_to_thread_queue(wakeup_request):
    pending_key = __get_pending_request_key(wakeup_request)
    with pending_lock:
        if pending_key in pending_requests:
            logger.debug("Skipping duplicate wake request for %s", pending_key)
            return
        pending_requests.add(pending_key)

    logger.debug("add new class to queue for wakeup thread")
    work_queue.put(wakeup_request)


def __get_pending_request_key(wakeup_request):
    """Return the deduplication key for a wakeup request."""
    return wakeup_request.pending_key or wakeup_request.searched_ip


if __name__ == "__main__":
    args = parse_args()
    logging.config.dictConfig(load_log_config(force_debug=args.debug))
    logger = logging.getLogger(__name__)

    logger.info("reading config file")
    __load_config()

    logger.info("setup thread queue")
    work_queue = queue.Queue()
    pending_lock = threading.Lock()
    pending_requests = set()

    loop_queue_check = threading.Thread(target=__check_thread_queue, daemon=True)
    logger.info("before running endless - queue check thread")
    loop_queue_check.start()

    try:
        logger.info("starting scapy sniffing packets")
        sniff(prn=__sniff_arp_and_dns, filter="arp[6:2] == 1 or udp dst port 53", store=0)
    except KeyboardInterrupt:
        logger.info("User requested shutdown")
        logger.info("Exiting")
        sys.exit(1)
    except Exception:
        __report_fatal_exception(EXCEPTION_MESSAGE)
        sys.exit(1)
