#!/bin/bash

# The VIP is directed to the katran instance

/data/xdplb --dest-mac=00-B0-D0-63-C2-26 --endpoint=10.111.222.11 --my-ip=10.111.221.11 --attach-to=eth0 --vip=192.168.10.1
