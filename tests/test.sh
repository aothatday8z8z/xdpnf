#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

clear_environment() {
  ip netns del ns1 2>/dev/null
  ip netns del ns2 2>/dev/null
  ip link del veth1 2>/dev/null
}

setup_environment() {
  # Create namespaces
  ip netns add ns1
  ip netns add ns2

  # Create veth pair
  ip link add veth1 type veth peer name veth2

  # Assign veth interfaces to namespaces
  ip link set veth1 netns ns1
  ip link set veth2 netns ns2

  # Assign IP addresses
  ip netns exec ns1 ip addr add 10.0.0.2/24 dev veth1
  ip netns exec ns2 ip addr add 10.0.0.3/24 dev veth2

  # Bring up interfaces
  ip netns exec ns1 ip link set veth1 up
  ip netns exec ns2 ip link set veth2 up

  # Test connectivity
  ip netns exec ns1 ping -c 3 10.0.0.3
}

get_interface_name() {
  local namespace=$1
  local ip_address=$2
  ip netns exec "$namespace" ip -o -4 addr show | awk -v ip="$ip_address" '$4 ~ ip {print $2}'
}

test_load() {
  local iname
  iname=$(get_interface_name ns1 10.0.0.2)
  if [ -n "$iname" ]; then
    xdpnf load "$iname"
  else
    echo "Interface not found in namespace ns1"
    exit 1
  fi
}

# Clear and set up the environment
clear_environment
setup_environment
get_interface_name
test_load