#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi


INTERFACE_NAME="s1"
MAX_CHAINS=32

die() {
  echo "$1" >&2
  exit 1
}


clear_environment() {
  ip netns del ns1 2>/dev/null
  ip netns del ns2 2>/dev/null
  ip netns del ns3 2>/dev/null
  ip link del ns1_out 2>/dev/null
  ip link del ns2_out 2>/dev/null
  ip link del ns3_out 2>/dev/null
  ovs-vsctl --if-exists del-br $INTERFACE_NAME
  ovs-vsctl add-br $INTERFACE_NAME
}

setup_environment() {
  # Create namespaces
  ip netns add ns1
  ip netns add ns2
  ip netns add ns3

  # Create veth pair
  ip link add ns1_in type veth peer name ns1_out
  ip link add ns2_in type veth peer name ns2_out
  ip link add ns3_in type veth peer name ns3_out

  # Assign veth interfaces to namespaces
  ip link set ns1_in netns ns1
  ip link set ns2_in netns ns2
  ip link set ns3_in netns ns3

  # Assign IP addresses
  ip addr add 10.0.0.1/24 dev $INTERFACE_NAME
  ip netns exec ns1 ip addr add 10.0.0.2/24 dev ns1_in
  ip netns exec ns2 ip addr add 10.0.0.3/24 dev ns2_in
  ip netns exec ns3 ip addr add 10.0.0.4/24 dev ns3_in

  # Bring up interfaces
  ip netns exec ns1 ip link set ns1_in up
  ip netns exec ns2 ip link set ns2_in up
  ip netns exec ns3 ip link set ns3_in up
  ip link set ns1_out up
  ip link set ns2_out up
  ip link set ns3_out up
  ip link set $INTERFACE_NAME up

  # Add port to ovs
  ovs-vsctl add-port $INTERFACE_NAME ns1_out
  ovs-vsctl add-port $INTERFACE_NAME ns2_out
  ovs-vsctl add-port $INTERFACE_NAME ns3_out

  # Get port numbers for the interfaces
  local ns1_out_port=$(ovs-vsctl get Interface ns1_out ofport)
  local ns2_out_port=$(ovs-vsctl get Interface ns2_out ofport)
  local ns3_out_port=$(ovs-vsctl get Interface ns3_out ofport)
  local host_dst_port=$(ovs-vsctl get Interface $INTERFACE_NAME ofport)

  # Add flow to OVS to match destination address with output port
  ovs-ofctl add-flow $INTERFACE_NAME "ip,nw_dst=10.0.0.2,actions=output:$ns1_out_port"
  ovs-ofctl add-flow $INTERFACE_NAME "ip,nw_dst=10.0.0.3,actions=output:$ns2_out_port"
  ovs-ofctl add-flow $INTERFACE_NAME "ip,nw_dst=10.0.0.4,actions=output:$ns3_out_port"
  # ovs-ofctl add-flow $INTERFACE_NAME "ip,nw_dst=10.0.0.1,actions=output:$INTERFACE_NAME"

  # Assign IPv6 addresses
  ip -6 addr add 2001:db8::1/64 dev $INTERFACE_NAME
  ip netns exec ns1 ip -6 addr add 2001:db8::2/64 dev ns1_in
  ip netns exec ns2 ip -6 addr add 2001:db8::3/64 dev ns2_in
  ip netns exec ns3 ip -6 addr add 2001:db8::4/64 dev ns3_in

  # Bring up IPv6 interfaces
  ip netns exec ns1 ip -6 link set ns1_in up
  ip netns exec ns2 ip -6 link set ns2_in up
  ip netns exec ns3 ip -6 link set ns3_in up
  ip -6 link set $INTERFACE_NAME up

  # Add IPv6 flow to OVS to match destination address with output port
  ovs-ofctl add-flow $INTERFACE_NAME "ipv6,ipv6_dst=2001:db8::2,actions=output:$ns1_out_port"
  ovs-ofctl add-flow $INTERFACE_NAME "ipv6,ipv6_dst=2001:db8::3,actions=output:$ns2_out_port"
  ovs-ofctl add-flow $INTERFACE_NAME "ipv6,ipv6_dst=2001:db8::4,actions=output:$ns3_out_port"
}

get_interface_name() {
  local namespace=$1
  local ip_address=$2
  
  ip netns exec "$namespace" ip -o -4 addr show | awk -v ip="$ip_address" '$4 ~ ip {print $2}'
}

test_load() {
  local rr
  rr=$(xdpnf load --mode skb $INTERFACE_NAME 2>&1)
  if [[ $rr == *"XDP program loaded on"* ]]; then
    echo "pass"
  else
    echo "fail"
  fi
}

ping_test() {
  ping -c 1 10.0.0.2 
  ping -c 1 10.0.0.3 
  ping -c 1 10.0.0.4 

  # IPv6 ping tests
  ping6 -c 1 2001:db8::2
  ping6 -c 1 2001:db8::3
  ping6 -c 1 2001:db8::4
}

generate_random_string() {
  local length=$1
  tr -dc A-Za-z0-9 </dev/urandom | head -c "$length"
}

test_new() {
  local policies=("" "-p drop" "-p accept")
  local success_count=0
  local fail_count=0
  for i in {1..50}; do
    local chain_name
    chain_name=$(generate_random_string 10)
    local policy
    policy=${policies[$RANDOM % ${#policies[@]}]}
    local output
    output=$(xdpnf new $policy "$chain_name" 2>&1)
    if [[ $output == *"Created chain"* ]]; then
      ((success_count++))
    else
      ((fail_count++))
    fi
  done
  if [ $success_count -ge $((MAX_CHAINS - 1)) ]; then
    echo "pass"
  else
    echo "fail"
  fi
}

test_unload() {
  local output
  output=$(xdpnf unload --all 2>&1)
  if [[ $output == *"XDP program unloaded"* ]]; then
    echo "pass"
  else
    echo "fail"
  fi
}

test_run() {
  echo "Testing load..."
  test_load
  echo "Testing new..."
  test_new
  echo "Testing unload..."
  test_unload
}

# Clear and set up the environment
clear_environment
setup_environment

# Run ping test
ping_test

# Run all tests
test_run

# test_load
# clear_environment
# clear_environment