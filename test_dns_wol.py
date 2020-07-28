from unittest.mock import mock_open
import unittest
from unittest import mock
from unittest.mock import patch, MagicMock
from dns_wol import (
    sendmail,
    icmp_check,
    sniff_arp_and_dns,
    get_hostname,
    load_config,
    add_paket_to_thread_queue,
)

from scapy.all import (
    ARP,
    IP,
    UDP,
    RandShort,
    DNSQR,
    DNSRR,
    DNS,
)
import queue
import logging
import yaml


class scapysniffTestCase(unittest.TestCase):

    @mock.patch("dns_wol.logging")
    @mock.patch("dns_wol.syslog")
    @mock.patch("dns_wol.time")
    @mock.patch("dns_wol.sr1")
    def test_icmp_check(self, mock_sr1, mock_time, mock_syslog, mock_logger):
        with open('log_config.yaml', 'r') as f:
            log_config = yaml.safe_load(f.read())
        logging.config.dictConfig(log_config)
        logger = logging.getLogger("__name__")
        load_config()
        # pkt = (
        #     IP(dst="192.168.1.1")
        #     / UDP(sport=RandShort(), dport=53)
        #     / DNS(rd=1, qd=DNSQR(qname="vdr", qtype="A"))
        # )
        mock_syslog.assert_any_call = "syslog"
        mock_sr1.return_value = None
        mock_time.sleep.return_value = None
        self.assertFalse(icmp_check("192.168.1.1"))
        mock_sr1.return_value = True
        self.assertTrue(icmp_check("192.168.1.1"))

    @mock.patch("dns_wol.socket.gethostbyaddr")
    def test_get_hostname(self, mock_socket):
        mock_socket.return_value = "testing"
        self.assertEqual(get_hostname('10.1.1.1'), "testing")

    def test_false_get_hostname(self):
        self.assertFalse(get_hostname("300.1.1.1"))

    @mock.patch("dns_wol.syslog")
    @mock.patch("dns_wol.sendmail")
    @mock.patch("dns_wol.time")
    @mock.patch("dns_wol.sr1")
    def test_sniff_with_dns_query(
        self, mock_sr1, mock_time, mock_sendmail, mock_syslog
    ):

        load_config()
        mock_sendmail.return_value = "sendmail"
        mock_syslog.assert_any_call = "syslog"
        mock_sr1.return_value = None
        mock_time.sleep.return_value = None
        pkt = (
            IP(dst="192.168.101.4")
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname="vdr", qtype="A"))
        )
        self.assertTrue(sniff_arp_and_dns(pkt))
        pkt = (
            IP(dst="192.168.101.4")
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=0, qd=DNSRR(rrname=b"vdr"))
        )
        self.assertFalse(sniff_arp_and_dns(pkt))

    @mock.patch("dns_wol.syslog")
    @mock.patch("dns_wol.smtplib")
    @mock.patch("dns_wol.time")
    @mock.patch("dns_wol.sr1")
    def test_sniff_with_arp_request(
        self, mock_sr1, mock_time, mock_sendmail, mock_syslog
    ):

        load_config()
        mock_sendmail.return_value = "sendmail"
        mock_syslog.assert_any_call = "syslog"
        mock_sr1.return_value = None
        mock_time.sleep.return_value = None
        pkt = ARP(op=1, psrc="192.168.101.123", pdst="192.168.101.4")
        self.assertTrue(sniff_arp_and_dns(pkt))
        pkt = ARP(op=2, psrc="192.168.101.123", pdst="192.168.101.4")
        self.assertFalse(sniff_arp_and_dns(pkt))

    @mock.patch("dns_wol.smtplib.SMTP")
    def test_sendmail(self, mock_sendmail):
        load_config()

        mock_sendmail.return_value.quit.return_value = (221, b'closing connection')
        self.assertTrue(sendmail("text", "from", "to")[0])
        self.assertEqual(sendmail("text", "from", "to")[1][0], int(221))
        mock_sendmail.return_value.quit.return_value = (222, b'other message')
        self.assertFalse(sendmail("text", "from", "to")[0])
        self.assertEqual(sendmail("text", "from", "to")[1][0], int(222))
    
    # @mock.patch("dns_wol.threading.Lock")
    # def test_add_paket_to_thread_queue(self, mock_thread):
    #     mock_thread.return_value(True)
    #     queueLock = mock()     
    #     workQueue = queue.Queue()
    #     add_paket_to_thread_queue("test")
    #     pkt = workQueue.get_nowait()
    #     self.assertEqual(pkt, "test")
        

if __name__ == "__main__":
    unittest.main()
