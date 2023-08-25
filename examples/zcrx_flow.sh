#!/bin/bash

ethtool -N eth0 flow-type tcp6 src-ip <ip address> dst-port 9999 action 1

ethtool -N eth0 flow-type tcp6 dst-port 0 m 0xfffe action 2
ethtool -N eth0 flow-type tcp6 dst-port 1 m 0xfffe action 2
