#!/bin/bash

# The default gateway is the router
# ip route add default via 10.111.222.11

# The vip is assigned to lo
ip addr add 192.168.10.1 dev lo

ip link add name ipip0 type ipip external
ip link set up dev ipip0

# echo server
python /data/echo.py
