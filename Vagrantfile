
Vagrant.configure('2') do |config|
  config.vm.hostname = "ubuntu-xdp"
  config.vm.box = "ubuntu/bionic64"

  config.vm.network :"private_network", type: "dhcp"
  config.vm.synced_folder "./", "/home/vagrant/gox"

  config.vm.provider :virtualbox do |v|
    v.name = "ubuntu-xdp"
    v.cpus = 1 
    v.memory = 1024
    v.customize ["modifyvm", :id, "--uartmode1", "disconnected"]
  end

  config.vm.provision "shell", privileged: true, inline: <<-SHELL
    wget -c https://kernel.ubuntu.com/~kernel-ppa/mainline/v4.18.20/linux-headers-4.18.20-041820-generic_4.18.20-041820.201812030624_amd64.deb
    wget -c https://kernel.ubuntu.com/~kernel-ppa/mainline/v4.18.20/linux-headers-4.18.20-041820_4.18.20-041820.201812030624_all.deb
    wget -c https://kernel.ubuntu.com/~kernel-ppa/mainline/v4.18.20/linux-image-unsigned-4.18.20-041820-generic_4.18.20-041820.201812030624_amd64.deb
    wget -c https://kernel.ubuntu.com/~kernel-ppa/mainline/v4.18.20/linux-modules-4.18.20-041820-generic_4.18.20-041820.201812030624_amd64.deb
    dpkg -i *.deb
  SHELL

  config.vm.provision "reload"

  config.vm.provision "shell", privileged: true, inline: <<-SHELL
    apt -y update
    apt install -y clang llvm libelf-dev libpcap-dev gcc-multilib build-essential make pkg-config
    cd /home/vagrant/gox/libbpf/src
    PKG_CONFIG_PATH=/build/root/lib64/pkgconfig DESTDIR=/build/root make install
  SHELL
end
