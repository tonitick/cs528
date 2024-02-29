#! /bin/bash
app_name=$1

make clean
make ${app_name}
sudo ./${app_name} -i tun0 -c 192.168.226.133 -d
