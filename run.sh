#!/bin/sh
socat -T15 udp4-recvfrom:53,reuseaddr,fork udp:thomas.bartsch.cl:54 &
socat -T15 tcp4-listen:53,reuseaddr,fork tcp:thomas.bartsch.cl:54 &
/ddns/docker-ddns.py
