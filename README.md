# gox
A program in XDP that encapsulates and decapsulates GTP-U packets.

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