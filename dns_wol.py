#!/usr/bin/env python3

import sys
from scapy.all import (
    ARP,
    IP,
    ICMP,
    DNS,
    sniff,
    sr1,
    conf,
)
from wakeonlan import send_magic_packet
import time
import os
import socket
import yaml
import smtplib
from email.parser import Parser
import threading
import queue
import logging
import logging.config


# static library variables
logging.getLogger("scapy.runtime").setLevel(logging.INFO)
conf.sniff_promisc = True

# own static constants
exception_message = "Exception occurred"
return_message = "return False"


class WakeupThread:
    """
    Stores attributes for monitored host to wakeup

    Attributes:
    searched_ip: monitored/listend ip / to wakeup
    :type searched_ip: str
    searched_mac: monitored/listend mac address / to wakeup
    :type searched_mac: str
    request_type: type of request - ARP (who is) or DNS name query
    :type request_type: str
    src_ip: orginating / source ip who has send this request
    :type src_ip: str
    searched_dns: queried dns name
    :type searched_dns: default == None or provided str
    """

    def __init__(
        self, searched_ip, searched_mac, request_type, src_ip, searched_dns=None
    ):
        """Initial class definition."""
        self.searched_ip = searched_ip
        self.searched_mac = searched_mac
        self.request_type = request_type
        self.src_ip = src_ip
        self.searched_dns = searched_dns


class Configuration:
    """Reads gerneral yaml Config file into class.

    Attributes:
        blocked_ip: IP Address of host system where this code runs on
        :type blocked_ip: list of str
        # blocked_mac: MAC Address of host system where this code runs on
        # :type blocked_mac: list of str
        listing_ip: list of ip address which will be monitored / watched for action
        :type listing_ip: list with str
        listing_mac: list of mac address which will be monitored / watched for action
        :type listing_mac: list with str
        listing_name: list of dns name which will be monitored / watched for action
        :type listing_name: list with str
        from_mail: from mail address
        :type from_mail: str
        to_mail: to send mail address
        :type to_mail: str
    """

    def __init__(self):
        """Initial class definition."""
        self.define_config_file()
        self.read_config(self.config_file)
        self.blocked_ip = self.config["blocked_ip"]
        self.monitoring = self.config["monitoring"]
        self.from_mail = self.config["from_mail"]
        self.to_mail = self.config["to_mail"]
        self.enable_mail = self.config["enable_mail"]
        self.wait_time = self.config["wait_time"]

    def read_config(self, config_file):
        """
        Reads config.yaml file into variables.

        :param none
        :return: config: variable
        :rtype: dict
        """
        with open(file=config_file, mode="r") as file:
            self.config = yaml.load(file, Loader=yaml.SafeLoader)
        logger.debug(self.config)

    def define_config_file(self):
        """
        Checks and defines Config yaml path.

        Defines a new class path atrribute.
        """
        if os.path.isfile(os.path.dirname(os.path.abspath(__file__)) + "/config.yaml"):
            self.config_file = (
                os.path.dirname(os.path.abspath(__file__)) + "/config.yaml"
            )
            logger.debug(self.config_file)
        else:
            print("else")
            self.config_file = (
                os.path.dirname(os.path.abspath(__file__)) + "/config_template.yaml"
            )
            logger.debug(self.config_file)


def sendmail(_text, _from, _to):
    """
    Send a message to via local message queue.

    :param _text: message text which will send
    :type _text: str
    :param _from: from mail address
    :type _from: str
    :param _to: to mail address
    :type _to: str
    :return: True/False, Tuple with smtp status code, message str
    :rtype: boolean, tuple(int(status_code),str(mesasge of code))
    """
    if config.enable_mail:
        _message = Parser().parsestr(
            f"From: <{_from}>\n"
            f"To: <{_to}>\n"
            f"Subject: {_text}\n"
            "\n"
            f"{_text}\n"
        )
        s = smtplib.SMTP("localhost")
        s.send_message(_message)
        result = s.quit()
        logger.debug(f"sendmail result code {result}")
        if result[0] == int(221):
            logger.debug(f"return True, {result}")
            return True, result
        else:
            logger.debug(f"return False, {result}")
            return False, result
    else:
        return False, "sendmail disabled"


def icmp_check(ipaddress):
    """
    Send a ping / icmp to ip to check if it is online.

    :param ipaddress: ip v4 address
    :type ipaddress: str
    :return: success / failed boolean
    :rtype: boolean
    """
    logger.info("ICMP checking if {0} is alive".format(ipaddress))
    ans1 = sr1(IP(dst=ipaddress) / ICMP(), timeout=1, verbose=0)
    logger.debug(f"first responce sr1={ans1}")
    time.sleep(0.5)
    resp = sr1(IP(dst=ipaddress) / ICMP(), timeout=1, verbose=0)
    logger.debug(f"second responce sr1={resp}")
    if resp is None:
        logger.debug("icmp check responce = None")
        logger.info("ICMP to IP {} is not answering".format(ipaddress))
        return False
    else:
        logger.debug("icmp check responce = {}".format(resp.summary()))
        logger.info("IP {} is alive!".format(ipaddress))
        return True


def wakeup_monitored_host(wakeup_class):
    """
    Wake monitored host / ip, if not alive via icmp

    :param wakeup_class: from scapy sniffed thread new created class WakeupThread for wakeup host
    :type _object_class_form_queue: class 
    :return: if wakeup performed = True / if host alive = False
    :rtype: boolean
    """
    try:
        if wakeup_class.searched_dns is None:
            _asked_for = wakeup_class.searched_ip
        else:
            _asked_for = wakeup_class.searched_dns
        logger.info(
            f"{wakeup_class.request_type} request detected - DNS {wakeup_class.src_ip} asks for {_asked_for}")

        icmp_result = icmp_check(wakeup_class.searched_ip)
        logger.debug(f"icmp_result: {icmp_result}")

        if icmp_result is False:
            logger.info(
                "WoL WakeUp - {0} Request detected - IP {1} asks for {2}".format(
                    wakeup_class.request_type,
                    wakeup_class.src_ip,
                    _asked_for
                )
            )

            logger.debug(f"send wol paket to MAC address {wakeup_class.searched_mac} of IP {wakeup_class.searched_ip}")
            send_magic_packet(wakeup_class.searched_mac)
            logger.debug("send now email about wakeup")
            sendmail(
                "WoL WakeUp - {0} Request detected - IP {1} asks for {2}".format(
                    wakeup_class.request_type,
                    wakeup_class.src_ip,
                    _asked_for,
                ),
                config.from_mail,
                config.to_mail,
            )

            logger.debug(f"now wait {config.wait_time} seconds to spin up host")
            time.sleep(config.wait_time)

            logger.debug("Method return True")
            return True

        else:
            logger.info(f"no wake up  - icmp check: host is alive!")
            logger.debug("Method return False")
            return False
    except Exception:
        logger.exception(exception_message, exc_info=True)

    logger.debug(return_message)
    return False


def arp_check(pkt):
    """Check ethernet packet for arp request

    Checks if an arp request is send for watched/monitored MAC address and
    sends than a WOL magic packet if IP is not alive/UP

    :param pkt: sniffed full ethernet packet
    :type pkt: class
    :return: give a boolean feedback if a wol was send or not
    # :rtype: boolean
    """
    logger.debug(f"check arp paket {pkt[ARP].op} == 1")
    if pkt[ARP].op == 1:
        searched_arp_ip = pkt[ARP].pdst
        requestor_arp_ip = pkt[ARP].psrc
        arp_asking_mac = pkt[ARP].hwsrc
        logger.debug(
            f"hwsrc {arp_asking_mac}; psrc {requestor_arp_ip}; pdst {searched_arp_ip}"
        )
        key, value = "ip", searched_arp_ip
        monitored_dict = [ listingDict for listingDict in config.monitoring if listingDict.get(key) == value ]
        logger.debug("monitored {} == searched {}".format(monitored_dict[0]['ip'],searched_arp_ip))
        if not bool(monitored_dict):
            if requestor_arp_ip not in config.blocked_ip or requestor_arp_ip != monitored_dict[0]['ip']:
                logger.debug("{} != {}".format(requestor_arp_ip, config.blocked_ip))
                wakeup_objects = WakeupThread(
                    searched_ip=searched_arp_ip,
                    searched_mac=monitored_dict[0]["mac"],
                    request_type="ARP",
                    src_ip=requestor_arp_ip,
                    searched_dns=None,
                )
                add_object_to_thread_queue(wakeup_objects)
                # return True

    logger.debug(return_message)
    # maybe to fix below for unwanted syslog output
    # return False


def dns_query_check(pkt):
    """Checks ethernet packet for dns query.

    Checks if an IP dns query is send/received for watched/monitored IP address and
    sends than a WOL magic packet if IP is not alive/UP

    :param pkt: sniffed full ethernet packet
    :type pkt: class
    :return: give a boolean feedback if a wol was send or not
    :rtype: boolean
    """
    try:
        logger.debug(
            f"check dns query {str(pkt.getlayer(DNS).qd.qname.decode('ASCII')).lower().rstrip('.')}"
        )
        key,value = 'dns_name',(pkt.getlayer(DNS).qd.qname.decode("ASCII")).lower().rstrip(".")
        monitored_dict = [ listingDict for listingDict in config.monitoring if listingDict.get(key) == value ]
        if not bool(monitored_dict):
            logger.info("monitored {} == searched {}".format(monitored_dict[0]['dns_name'], str(
                pkt.getlayer(DNS).qd.qname.decode('ASCII')).lower().rstrip('.')))
            ip_src = pkt[IP].src
            dns_name = (
                str(pkt.getlayer(DNS).qd.qname.decode("ASCII")).lower().rstrip(".")
            )
            if ip_src != monitored_dict[0]['ip'] or ip_src not in config.blocked_ip: 
                wakeup_objects = WakeupThread(
                    searched_ip=monitored_dict[0]["ip"],
                    searched_mac=monitored_dict[0]["mac"],
                    request_type="DNS Query",
                    src_ip=ip_src,
                    searched_dns=dns_name,
                )
                add_object_to_thread_queue(wakeup_objects)
            # return True
    except Exception:
        logger.exception(exception_message, exc_info=True)

    logger.debug(return_message)
    # return False


def sniff_arp_and_dns(pkt):
    """Precheck sniffed ethernet packet for arp or dns query.

    Sniffed ethernet packet will be further checked,
    if it is a IP packet with DNS query or
    if it is a ARP packet.

    :param pkt: sniffed full ethernet packet
    :type pkt: class
    :return: give result of sub method back
    :rtype: result: boolean
    """
    result = None
    logger.debug(f"sniffed paket to check: {pkt.summary()}")
    # show full paket to stdout
    # logger.debug(pkt.show())
    if ARP in pkt:
        logger.debug("ARP paket detected")
        result = arp_check(pkt)

    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        logger.debug("DNS paket detected")
        result = dns_query_check(pkt)
    logger.debug(f"return result {result}")
    # return result

def load_config():
    """Load config file.

    Loads config file into a class object which gloablly available variable.

    :return: global config class variable
    :rtype: class
    """
    global config
    config = Configuration()


def check_thread_queue():

    logger.info("starting endless check queue loop")

    while True:
        if not workQueue.empty():
            logger.debug("get queue paket")
            queueLock.acquire()
            _object_class = workQueue.get_nowait()
            wakeup_monitored_host(_object_class)
            queueLock.release()
        # else:
        #     logger.debug("empty queue")

        time.sleep(0.01)


def add_object_to_thread_queue(_object_class):

    queueLock.acquire()
    logger.debug("add new class to queue for wakeup thread")
    workQueue.put(_object_class)
    queueLock.release()


if __name__ == "__main__":
    """Main method"""
    with open(
        file=os.path.dirname(os.path.abspath(__file__)) + "/log_config.yaml", mode="r"
    ) as file:
        log_config = yaml.load(file, Loader=yaml.SafeLoader)
        logging.config.dictConfig(log_config)
    logger = logging.getLogger(__name__)

    logger.info("reading config file")
    load_config()

    logger.info("setup thread queue")
    queueLock = threading.Lock()
    workQueue = queue.Queue()

    loop_queue_check = threading.Thread(target=check_thread_queue)
    logger.info("before running endless - queue check thread")
    loop_queue_check.start()

    try:
        logger.info("starting scapy sniffing pakets")
        sniff(prn=sniff_arp_and_dns, filter="arp[6:2] == 1 or udp dst port 53", store=0)
    except KeyboardInterrupt:
        logger.exception(exception_message, exc_info=True)
        logger.info("User Requested Shutdown...")
        logger.info("Exiting...")
        sys.exit(1)

    logger.info("wait for the thread to finish")
    logger.info("all done")
