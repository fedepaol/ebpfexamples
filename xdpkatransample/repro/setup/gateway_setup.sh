#!/bin/bash

# send everything to katran
ip route del default
ip route add default via 10.111.221.11

sleep inf