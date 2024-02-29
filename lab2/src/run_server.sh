#! /bin/bash
app_name=$1

make clean
make ${app_name}
sudo ./${app_name} -i tun0 -s -d
