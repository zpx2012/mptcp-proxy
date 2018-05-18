#!/bin/bash

sudo openvpn --config /home/alan/client1.ovpn --daemon openvpn_test --log /home/alan/vpntest_result/openvpn.log.`date +%Y%m%d` --writepid /home/alan/openvpn.pid

sleep 60

curl www.google.com > /home/alan/vpntest_result/`date +%Y%m%d`-01

sleep 120

curl www.google.com > /home/alan/vpntest_result/`date +%Y%m%d`-02

sleep 120

curl www.google.com > /home/alan/vpntest_result/`date +%Y%m%d`-03

sleep 3

sudo kill -INT `cat /home/alan/openvpn.pid`


