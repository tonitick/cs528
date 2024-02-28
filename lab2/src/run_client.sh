#! /bin/bash
app_name=$1

gcc ${app_name}.c -o ${app_name}
sudo ./${app_name} -i tun0 -c 192.168.226.133 -d
