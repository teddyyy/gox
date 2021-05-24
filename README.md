# gox
A program in XDP that encapsulates and decapsulates GTP-U packets. This is for study and hobby.

## system components
![components](https://user-images.githubusercontent.com/1239380/119367836-54bee600-bced-11eb-98e5-e3d3d686c169.jpg)

## gox_user
gox_user is a userspace application that loads or unloads the XDP program(gox_kern).
It receives messages from goxctl over the unix domain socket and updates or deletes forwarding rules the eBPF Map.
```
$ ./gox_user -h
Usage:
-r <raw iface name>: Name of interface to receive raw packet (mandatory)
-g <gtpu iface name>: Name of interface to receive GTPU packet (mandatory)
-s <gtpu source address>: Address when sending GTPU packet (mandatory)
```

## gox_kern
gox_kern is a data plane application that encapsulates and decapsulates gtpu packets according to the eBPF Map.
It consists of two programs that encapsulate and decapsulate. Therefore, gox needs more than two network interfaces.
gox currently supports only IPv4, and when other protocols (ARP, IPv6, etc.) are received, they will be passed from gox_kern to the network stack. It also refers to the Linux FIB for forwarding packets.

## goxctl
goxctl is a CLI tool for requesting to update or delete forwarding rules to eBPF Map.
The PDR uses the teid or UE address as the key for the eBPF Map. Key of teid can be set for the GTP-U receive interface and key of UE address can be set for the Raw interface.The FAR is tied to the PDR, and when encapsulating it, the teid and IPv4 address must be configured. (Not required for decapsulation).
```
Usage: goxctl [object] [command] [params]
        object: [ pdr | far ]
        command: [ add | del ]
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

on VM
```
cd gox
make
```