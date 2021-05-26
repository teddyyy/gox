# !/bin/bash
set -eu

# Delete all existing namespaces
sudo ip -all netns delete 

# Create namespace 
sudo ip netns add ue
sudo ip netns add ran
sudo ip netns add upf
sudo ip netns add dn

# Create interface
sudo ip link add name ue-veth1 type veth peer name ran-veth1
sudo ip link add name ran-veth2 type veth peer name upf-veth1
sudo ip link add name upf-veth2 type veth peer name dn-veth1

# Make the interface belong to each namespace 
sudo ip link set ue-veth1 netns ue
sudo ip link set ran-veth1 netns ran
sudo ip link set ran-veth2 netns ran
sudo ip link set upf-veth1 netns upf
sudo ip link set upf-veth2 netns upf
sudo ip link set dn-veth1 netns dn

# Add IP Address to each interface
sudo ip netns exec ue ip addr add 10.0.0.1/24 dev ue-veth1
sudo ip netns exec ran ip addr add 10.0.0.254/24 dev ran-veth1
sudo ip netns exec ran ip addr add 192.168.0.1/24 dev ran-veth2
sudo ip netns exec upf ip addr add 192.168.0.2/24 dev upf-veth1
sudo ip netns exec upf ip addr add 172.16.0.254/24 dev upf-veth2
sudo ip netns exec dn ip addr add 172.16.0.1/24 dev dn-veth1

# Up interface
sudo ip netns exec ue ip link set ue-veth1 up
sudo ip netns exec ran ip link set ran-veth1 up
sudo ip netns exec ran ip link set ran-veth2 up
sudo ip netns exec upf ip link set upf-veth1 up
sudo ip netns exec upf ip link set upf-veth2 up
sudo ip netns exec dn ip link set dn-veth1 up
sudo ip netns exec ue ip link set lo up
sudo ip netns exec ran ip link set lo up
sudo ip netns exec upf ip link set lo up
sudo ip netns exec dn ip link set lo up

# Add routing & forwarding
sudo ip netns exec ue ip route add 0.0.0.0/0 via 10.0.0.254
sudo ip netns exec dn ip route add 0.0.0.0/0 via 172.16.0.254
sudo ip netns exec ran ip route add 172.16.0.0/24 via 192.168.0.2 dev ran-veth2
sudo ip netns exec upf ip route add 10.0.0.0/24 via 192.168.0.1 dev upf-veth1
sudo ip netns exec ran sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec upf sysctl -w net.ipv4.ip_forward=1

