#! /bin/bash
app_name=minivpn_task6_server

make clean
make ${app_name}
sudo ./${app_name} -s -d
