[![GitHub Action Status](https://github.com/OliverDrechsler/MADwaS/workflows/MADwaS/badge.svg)](https://github.com/OliverDrechsler/MADwaS/workflows/MADwaS/badge.svg)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=OliverDrechsler_MADwaS&metric=alert_status)](https://sonarcloud.io/dashboard?id=OliverDrechsler_MADwaS)
[![CodeFactor](https://www.codefactor.io/repository/github/oliverdrechsler/madwas/badge)](https://www.codefactor.io/repository/github/oliverdrechsler/madwas)
[![wemake-python-styleguide](https://img.shields.io/badge/style-wemake-000000.svg)](https://github.com/wemake-services/wemake-python-styleguide)
[![Updates](https://pyup.io/repos/github/OliverDrechsler/MADwaS/shield.svg)](https://pyup.io/repos/github/OliverDrechsler/MADwaS/)
[![Python 3](https://pyup.io/repos/github/OliverDrechsler/MADwaS/python-3-shield.svg)](https://pyup.io/repos/github/OliverDrechsler/MADwaS/)
[![Known Vulnerabilities](https://snyk.io/test/github/OliverDrechsler/MADwaS/badge.svg)](https://snyk.io/test/github/OliverDrechsler/MADwaS)


# MADwaS - Monitor ARP queries and DNS queries to wakeup a Server

- [MADwaS - Monitor ARP queries and DNS queries to wakeup a Server](#madwas---monitor-arp-queries-and-dns-queries-to-wakeup-a-server)
  - [Intro](#intro)
  - [UseCase](#usecase)
  - [minimum requirements](#minimum-requirements)
  - [first time setup](#first-time-setup)
  - [run script as a systemd service](#run-script-as-a-systemd-service)
  - [config.yaml parameters should be self explained](#configyaml-parameters-should-be-self-explained)


## Intro

MADwaS - (M)onitor (A)RP queries and (D)NS queries to (w)akeup (a) (S)erver

This script sniffs on a network interface for:  

- DNS Name query request  
and / or
- ARP (who has) IPAddress request  

It checks if a destination ip (server) is alive via icmp.  
If not it sends a wake on lan magic packet and waits for a defined time period for the next check.  
If a wakeup paket is send, it sends via local available mail service a notification mail about the wake up event.  

## UseCase

I run at home a [VDR](http://tvdr.de/) home theater pc.  
This computer also acts as my file server (samba).  
To save power consumption, this PC is often powered of.  
It powers it self on for recording TV shows and powers off it self.  
For that i use some plugins like [EPGSearch](http://www.vdr-wiki.de/wiki/index.php/Epgsearch-plugin) and [ACPIWakeup](http://www.vdr-wiki.de/wiki/index.php/ACPI_Wakeup).  
So, mostly when i want to access my files the VDR is often powered off and my  
File Server is not accessable.  
To power on my VDR via LAN, i use the [wake on lan](http://www.vdr-wiki.de/wiki/index.php/WAKE_ON_LAN) feature.  
But there's no independend place who does it automatically for my.  
Okay, you can maybe run a wake on lan script on your client PC.  
But i want automaticylly power on my VDR File Server when i come at home.  
I use the [PhotoSync](https://www.photosync-app.com/de/index.html) App on my smartphone  
to automatically tranfer all new photos to the VDR Server.  
This is done via GeoFencing and when my smartphone connects into my WLAN.  
So, i must nothing do, magic things happens and i have every time my fotos backuped.  

For that use case i need a independend third instance.  
I have a Raspberry Pi running in my LAN which permanently powered on.  
[PIHOLE](https://pi-hole.net/) runs on this one, but this does not play a role for my program/script.  
It just has to run permanently somewhere.  

## minimum requirements

- sudo / root permissions to run dns_wol.py script
- min. Python 3.6 
- Python pip installed
- sendmail or other mail daemon running on host to send a mail i case of a wake up event occured  
- LAN interface must be in the same LAN/VLAN or WLAN as File Server

LAN Device dependend capability:

- connected to a LAN Switch Device - only ARP (who has) queries will work
- connected to a LAN HUB Device - DNS queries will work
- connected to a LAN Switch Device - but script runs on a DNS Server or [PiHole](https://pi-hole.net/), DNS queries will also work
- connected to WLAN - WLAN Router must allow communication between WLAN Device - otherwise nothing will work.

Host:

- must be every time powered on


## first time setup

clone repo and configure settings
```bash
git clone https://github.com/od2017/MADwaS.git
cd MADwaS
cp dns_wol.py /usr/local/bin
cp config_template.yaml /usr/bin/local/config.yaml
cp log_config /usr/bin/local
vi /usr/local/bin/config.yaml  # modify config.yaml to your needs
```

install python dependencies
```bash
pip install -r requirements
python3 dns_wol.py  # run first time - test and watch console output
``` 

## run script as a systemd service

The file `dns_wol.service` is a example file for systemd and must be adjusted to  
your personal needs. Copy the file to `/etc/systemd/system`.  
And run bash `systemctl enable dns_wol.service` command to enable this new service.  
To start service run `systemctl start dns_wol.service`  

## config.yaml parameters should be self explained

```config.yaml
Customize in the config.yaml with following vars:  
own_ip: "<host ip where script runs on>"  
own_mac: "<mac address where script runs on>"  
  
listening_name:  
  - "<list of dnsname query to be listened to>"  
  - "<second name entry>"  
  
listening_ip: "<ip address to be listened to>"  
listening_mac: "<mac address of which the arp request to be listened to>"  
  
from_mail: "<local sendmail daemon from mail address>"  
to_mail: "<local sendmail daemon to mail address>"  
enable_mail: "<enable sendmail on wakeup event: True/False>"
```

<details>
  <summary>📚 Imprint and GDPDR / Impressum und DSGVO</summary>

   <a href="https://github.com/OliverDrechsler/Impressum#readme" onclick="popup=window.open('https://github.com/OliverDrechsler/Impressum#readme','Imprintpopup','width=580,height=635'); return false;">click here to see Imprint / Impressum</a>

   <a href="https://github.com/OliverDrechsler/DSGVO#readme" onclick="popup=window.open('https://github.com/OliverDrechsler/DSGVO#readme','DSGVOpopup','width=580,height=635'); return false;">click here to see GDPDR / DSGVO</a>
   