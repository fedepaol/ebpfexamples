#!/bin/bash

# Default route via the gateway
ip route del default
ip route add default via 10.111.222.12

# The vip is assigned to lo
ip addr add 192.168.10.1 dev lo

ip link add name ipip0 type ipip external
ip link set up dev ipip0
ip a a 127.0.0.42/32 dev ipip0

# echo server
python /data/echo.py
