#! /bin/bash

sshpass -p 'dees' rsync -avz   ./ u12:/home/seed/zzhong/hw/cs528/lab2/src
sshpass -p 'dees' rsync -avz ./ u12-2:/home/seed/zzhong/hw/cs528/lab2/src
