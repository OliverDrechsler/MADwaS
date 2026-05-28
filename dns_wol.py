#!/usr/bin/env python3

import logging
import logging.config
import queue
import smtplib
import socket
import sys
import threading
import time
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

import yaml
from scapy.all import ARP, DNS, ICMP, IP, conf, sniff, sr1
from wakeonlan import send_magic_packet


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.sniff_promisc = True

EXCEPTION_MESSAGE = "Exception occurred"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"
CONFIG_TEMPLATE_PATH = BASE_DIR / "config_template.yaml"
LOG_CONFIG_PATH = BASE_DIR / "log_config.yaml"

logger = logging.getLogger(__name__)
config = None
work_queue = None
pending_lock = threading.Lock()
pending_requests = set()


@dataclass(frozen=True, slots=True)
class WakeupRequest:
    searched_ip: str
    searched_mac: str
    request_type: str
    src_ip: str
    searched_dns: Optional[str] = None


class Configuration:
    """Read the YAML config and prepare lookup tables."""

    def __init__(self):
        self.config_file = CONFIG_PATH if CONFIG_PATH.is_file() else CONFIG_TEMPLATE_PATH
        logger.debug("Using config file %s", self.config_file)
        self.config = self.read_config(self.config_file)
        self.blocked_ip = set(self.config.get("blocked_ip", []))
        self.monitoring = self.config.get("monitoring", [])
        self.from_mail = self.config.get("from_mail", "")
        self.to_mail = self.config.get("to_mail", "")
        self.enable_mail = bool(self.config.get("enable_mail", False))
        self.wait_time = int(self.config.get("wait_time", 45))
        self.local_ip = discover_local_ipv4_addresses()
        self.monitoring_by_ip = {}
        self.monitoring_by_dns = {}
        self._build_lookup_tables()

    @staticmethod
    def read_config(config_file):
        with open(file=config_file, mode="r", encoding="utf-8") as file:
            config = yaml.safe_load(file) or {}
        logger.debug("Loaded config: %s", config)
        return config

    def _build_lookup_tables(self):
        for entry in self.monitoring:
            ip_address = entry.get("ip")
            dns_name = str(entry.get("dns_name", "")).lower().rstrip(".")
            if not ip_address or not entry.get("mac"):
                logger.warning("Skipping invalid monitoring entry: %s", entry)
                continue
            self.monitoring_by_ip[ip_address] = entry
            if dns_name:
                normalized_entry = dict(entry)
                normalized_entry["dns_name"] = dns_name
                self.monitoring_by_dns[dns_name] = normalized_entry


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


def discover_local_ipv4_addresses():
    """Collect IPv4 addresses assigned to the local host."""
    local_ips = {"127.0.0.1"}
    for iface in conf.ifaces.values():
        iface_ip = getattr(iface, "ip", None)
        if iface_ip and "." in str(iface_ip):
            local_ips.add(str(iface_ip))

    try:
        host_entries = socket.getaddrinfo(
            socket.gethostname(),
            None,
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
        )
        for entry in host_entries:
            ip_address = entry[4][0]
            if ip_address:
                local_ips.add(ip_address)
    except OSError:
        logger.debug("Unable to resolve local host addresses via getaddrinfo")

    logger.info("Ignoring packets originating from local IPs: %s", sorted(local_ips))
    return local_ips


def icmp_check(ipaddress, attempts=2, timeout=1):
    """Send ICMP echo requests to check if an IP is online."""
    logger.info("ICMP checking if %s is alive", ipaddress)
    for attempt in range(1, attempts + 1):
        response = sr1(IP(dst=ipaddress) / ICMP(), timeout=timeout, verbose=0)
        logger.debug("icmp attempt %s response=%s", attempt, response)
        if response is not None:
            logger.info("IP %s is alive", ipaddress)
            return True
    logger.info("ICMP to IP %s is not answering", ipaddress)
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

        if icmp_check(wakeup_request.searched_ip):
            logger.info("No wake up needed - host %s is alive", wakeup_request.searched_ip)
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
        clear_pending_request(wakeup_request.searched_ip)


def arp_check(pkt):
    """Check if an ARP request targets a monitored host."""
    logger.debug("check arp packet %s == 1", pkt[ARP].op)
    if pkt[ARP].op != 1:
        return

    searched_arp_ip = pkt[ARP].pdst
    requestor_arp_ip = pkt[ARP].psrc
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

    if requestor_arp_ip in config.blocked_ip or requestor_arp_ip == monitored_entry["ip"]:
        return

    logger.debug("ARP request accepted from %s", requestor_arp_ip)
    add_object_to_thread_queue(
        WakeupRequest(
            searched_ip=searched_arp_ip,
            searched_mac=monitored_entry["mac"],
            request_type="ARP",
            src_ip=requestor_arp_ip,
        )
    )


def dns_query_check(pkt):
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
        ip_src = pkt[IP].src
        if ip_src in config.local_ip:
            logger.debug("Ignoring locally generated DNS request from %s", ip_src)
            return

        if ip_src in config.blocked_ip or ip_src == monitored_entry["ip"]:
            return

        logger.debug("DNS request accepted from %s", ip_src)
        add_object_to_thread_queue(
            WakeupRequest(
                searched_ip=monitored_entry["ip"],
                searched_mac=monitored_entry["mac"],
                request_type="DNS Query",
                src_ip=ip_src,
                searched_dns=dns_name,
            )
        )
    except Exception:
        logger.exception(EXCEPTION_MESSAGE, exc_info=True)


def sniff_arp_and_dns(pkt):
    """Pre-check sniffed ethernet packets for ARP or DNS queries."""
    logger.debug("sniffed packet to check: %s", pkt.summary())
    if ARP in pkt:
        logger.debug("ARP packet detected")
        arp_check(pkt)

    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        logger.debug("DNS packet detected")
        dns_query_check(pkt)


def load_config():
    global config
    config = Configuration()


def clear_pending_request(ip_address):
    with pending_lock:
        pending_requests.discard(ip_address)


def check_thread_queue():
    logger.info("starting endless check queue loop")
    while True:
        wakeup_request = work_queue.get()
        try:
            wakeup_monitored_host(wakeup_request)
        finally:
            work_queue.task_done()


def add_object_to_thread_queue(wakeup_request):
    with pending_lock:
        if wakeup_request.searched_ip in pending_requests:
            logger.debug("Skipping duplicate wake request for %s", wakeup_request.searched_ip)
            return
        pending_requests.add(wakeup_request.searched_ip)

    logger.debug("add new class to queue for wakeup thread")
    work_queue.put(wakeup_request)


if __name__ == "__main__":
    with open(file=LOG_CONFIG_PATH, mode="r", encoding="utf-8") as file:
        log_config = yaml.safe_load(file)
        logging.config.dictConfig(log_config)
    logger = logging.getLogger(__name__)

    logger.info("reading config file")
    load_config()

    logger.info("setup thread queue")
    work_queue = queue.Queue()
    pending_lock = threading.Lock()
    pending_requests = set()

    loop_queue_check = threading.Thread(target=check_thread_queue, daemon=True)
    logger.info("before running endless - queue check thread")
    loop_queue_check.start()

    try:
        logger.info("starting scapy sniffing packets")
        sniff(prn=sniff_arp_and_dns, filter="arp[6:2] == 1 or udp dst port 53", store=0)
    except KeyboardInterrupt:
        logger.info("User requested shutdown")
        logger.info("Exiting")
        sys.exit(1)
    except Exception:
        logger.exception(EXCEPTION_MESSAGE, exc_info=True)
        sys.exit(1)
