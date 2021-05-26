# gox
A program in XDP that encapsulates and decapsulates GTP-U packets. This is for study and hobby.

## system components
![components](https://user-images.githubusercontent.com/1239380/119367836-54bee600-bced-11eb-98e5-e3d3d686c169.jpg)

## gox_user
gox_user is a userspace application that loads or unloads the XDP program(gox_kern).
It receives messages from goxctl over the unix domain socket and updates or deletes forwarding rules the eBPF Map.
```
./gox_user -h
Usage:
        -r <raw iface name>: Name of interface to receive raw packet (mandatory)
        -g <gtpu iface name>: Name of interface to receive GTPU packet (mandatory)
        -s <gtpu source address>: Address when sending GTPU packet (mandatory)
        -p <unix domain socket path>: Path of unix socket to listen (default: /var/run/gox)
```

## gox_kern
gox_kern is a data plane application that encapsulates and decapsulates gtpu packets according to the eBPF Map.
It consists of two programs that encapsulate and decapsulate. Therefore, gox needs more than two network interfaces.
gox currently supports only IPv4, and when other protocols (ARP, IPv6, etc.) are received, they will be passed from gox_kern to the network stack. It also refers to the Linux FIB for forwarding packets.

## goxctl
goxctl is a CLI tool for requesting to update or delete forwarding rules to eBPF Map.
The PDR uses the teid or UE address as the key for the eBPF Map. Key of teid can be set for the GTP-U receive interface and key of UE address can be set for the Raw interface.The FAR is tied to the PDR, and when encapsulating it, the teid and IPv4 address must be configured. (Not required for decapsulation).
```
./goxctl -h
Usage:
        -p <unix domain socket path>: Path of unix socket to connect (default: /var/run/gox)
        -c <command>: Commands for manipulating the eBPF map
                format [object] [operation] [params]
                object: [ pdr | far ]
                operation: [ add | del ]
                params pdr add: [ifname] [ self teid | ue addr ] [far id]
                params pdr del: [ifname] [ self teid | ue addr ]
                params far add: [far id] <teid> <peer addr>
                params far del: [far id]
```

## Running gox on Virtalbox
on Host
```
vagrant plugin install vagrant-reload vagrant-vbguest
vagrant up
vagrant ssh
```

build
```
cd gox
make
```

create network using namespaces
```
./tools/create_ns.sh
```

execute gox as upf
```
sudo ip netns exec upf ./gox_user -r upf-veth2 -g upf-veth1 -s 192.168.0.2 &
```

execute gox as ran
```
sudo ip netns exec ran ./gox_user -r ran-veth1 -g ran-veth2 -s 192.168.0.1 -p "/var/run/ran" &
```

add forwarding rules (from dn to ue)
```
sudo ip netns exec upf ./goxctl -c "far add 11 101 192.168.0.1"
sudo ip netns exec upf ./goxctl -c "far add 22"
sudo ip netns exec upf ./goxctl -c "pdr add upf-veth2 10.0.0.1 11"
sudo ip netns exec upf ./goxctl -c "pdr add upf-veth1 202 22"
```

add forwarding rules (from ue to dn)
```
sudo ip netns exec ran ./goxctl -c "pdr add ran-veth1  172.16.0.1 11" -p "/var/run/ran"
sudo ip netns exec ran ./goxctl -c "pdr add ran-veth2  101 22" -p "/var/run/ran"
sudo ip netns exec ran ./goxctl -c "far add 11 202 192.168.0.2" -p "/var/run/ran"
sudo ip netns exec ran ./goxctl -c "far add 22" -p "/var/run/ran"
```