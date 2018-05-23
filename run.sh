#!/bin/bash

sudo mpproxy start || echo "mptcp_proxy not found. Maybe run make first."
#sudo ./mptcp_proxy