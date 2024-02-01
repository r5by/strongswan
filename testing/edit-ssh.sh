#!/bin/bash

# Equivalent to `ssh -o StrictHostKeyChecking=no root@moon` but don't need to pass `-o` options everytime

DIR=$(dirname `readlink -f $0`)
. $DIR/testing.conf
. $DIR/scripts/function.sh

# Define the host and its associated options
#HOST_NAME="moon"
OPTIONS="StrictHostKeyChecking no"

# Check if the config file exists, and create it if not
CONFIG_FILE="$HOME/.ssh/config"
if [ ! -f "$CONFIG_FILE" ]; then
    touch "$CONFIG_FILE"
fi

for host in $STRONGSWANHOSTS
do
	# Check if the host entry already exists in the config file
  if grep -q "^Host ${host}$" "$CONFIG_FILE"; then
      # Host entry exists, update the existing options
      sed -i "/^Host ${host}$/,/^$/ s/^$OPTIONS.*/$OPTIONS/" "$CONFIG_FILE"
  else
      # Host entry does not exist, add a new entry
      echo -e "\nHost ${host}\n\t$OPTIONS" >> "$CONFIG_FILE"
  fi
done
