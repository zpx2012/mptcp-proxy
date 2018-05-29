#!/bin/bash
chmod 400 ~/mptcp-proxy/test/mptcp_aws_1.pem
ssh -D 127.0.0.1:1080 -i "~/mptcp-proxy/test/mptcp_aws_1.pem" ubuntu@ec2-52-33-71-249.us-west-2.compute.amazonaws.com
