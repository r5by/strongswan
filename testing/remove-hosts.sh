#!/bin/bash

DIR=$(dirname `readlink -f $0`)
. $DIR/testing.conf
. $DIR/scripts/function.sh


sudo sed -i '/^# DNS resolver for libvirt VM.*$/d' /etc/hosts >/dev/null

current_host=$(hostname)
for host in $STRONGSWANHOSTS
do
# Exclude the current hostname from deletion
    if [ "$host" != "$current_host" ]; then
        # Remove ipv4_${host} entry
        sudo sed -i "/^.*${host}\$/d" /etc/hosts >/dev/null
    fi
done

#host="alice"
#sudo sed -i "/^.*${host}\$/d" /etc/hosts >/dev/null

# echo "DNS resolver entries removed."
