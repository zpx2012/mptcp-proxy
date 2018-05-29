#!/bin/bash
sudo apt-get update
sudo apt-get install -y libnetfilter-queue-dev libnfnetlink-dev redis-server libhiredis-dev libev-dev python-redis python-scapy openvpn easy-rsa
sudo apt-get install -y python-pip libcurl4-gnutls-dev python-dev libgnutls28-dev shadowsocks
sudo pip install pycurl
