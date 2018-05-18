#!/bin/bash

sudo openvpn --config /home/pengxiong/mptcp-proxy/test_case/client1.ovpn --log /home/pengxiong/mptcp-proxy/test_case/vpntest_result/openvpn.log.`date +%Y%m%d` --writepid /home/pengxiong/mptcp-proxy/test_case/openvpn.pid

sleep 60

curl www.google.com > /home/pengxiong/mptcp-proxy/test_case/vpntest_result/`date +%Y%m%d`-01

sleep 120

curl www.google.com > /home/pengxiong/mptcp-proxy/test_case/vpntest_result/`date +%Y%m%d`-02

sleep 120

curl www.google.com > /home/pengxiong/mptcp-proxy/test_case/vpntest_result/`date +%Y%m%d`-03

sleep 3

sudo kill -INT `cat /home/pengxiong/mptcp-proxy/test_case/openvpn.pid`


