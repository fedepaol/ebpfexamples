#!/bin/bash

# The default gateway is the router
ip route add default via 10.111.222.11

# The vip is assigned to lo
ip addr add 192.168.10.1 dev lo

# echo server
ncat -l 2000 -k -c 'xargs -n1 echo'
