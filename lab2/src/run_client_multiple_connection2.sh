#! /bin/bash
app_name=minivpn_task6_client

make clean
make ${app_name}
sudo ./${app_name} -i tun1 -c 192.168.226.133 -d
