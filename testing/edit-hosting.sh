#!/bin/bash

DIR=$(dirname `readlink -f $0`)
. $DIR/testing.conf
. $DIR/scripts/function.sh

#host="alice"
#eval ipv4_${host}="`echo $HOSTNAMEIPV4 | sed -n -e "s/^.*${host},//gp" | awk -F, '{ print $1 }' | awk '{ print $1 }'`"
#eval ipv4_alice1="`echo $HOSTNAMEIPV4 | sed -n -e "s/^.*${host},//gp" | awk -F, '{ print $2 }' | awk '{ print $1 }'`"
#echo "$ipv4_alice"
#echo "$ipv4_alice1"
##############################################################################
# assign IP for each host to hostname
#
echo "# DNS resolver for libvirt VM's (strongswan testing)" | sudo tee -a /etc/hosts >/dev/null
for host in $STRONGSWANHOSTS
do
	eval ipv4_${host}="`echo $HOSTNAMEIPV4 | sed -n -e "s/^.*${host},//gp" | awk -F, '{ print $1 }' | awk '{ print $1 }'`"
	eval ipv6_${host}="`echo $HOSTNAMEIPV6 | sed -n -e "s/^.*${host},//gp" | awk -F, '{ print $1 }' | awk '{ print $1 }'`"

  ipv4_addr=ipv4_${host}
  echo "${!ipv4_addr} ${host}" | sudo tee -a /etc/hosts >/dev/null

done

# Function to add entries to /etc/hosts
#add_entries() {
#    local entries=$1
#    echo "# Hostname to IP Mapping" | sudo tee -a /etc/hosts
#    while IFS=, read -r hostname ip_entries; do
#        for ip in $ip_entries; do
#            echo "$ip $hostname" | sudo tee -a /etc/hosts
#            echo "Added entry: $ip $hostname"
#        done
#    done <<< "$entries"
#}
#
## Add IPv4 entries
#add_entries "$HOSTNAMEIPV4"
#
## Add IPv6 entries
#add_entries "$HOSTNAMEIPV6"
