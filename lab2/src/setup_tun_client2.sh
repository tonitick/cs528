#! /bin/bash

sudo ip addr add 10.0.4.1/24 dev tun1
sudo ifconfig tun1 up
sudo route add -net 10.0.3.0 netmask 255.255.255.0 dev tun1

