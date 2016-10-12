# -*- mode: ruby -*-
# vi: set ft=ruby :

# This vagrant sets up build environment for mirai botnet
Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://atlas.hashicorp.com/search.
  config.vm.box = "ubuntu/trusty64"

  # Enable provisioning with a shell script. Additional provisioners such as
  # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
  # documentation for more information about their specific syntax and use.
   config.vm.provision "shell", inline: <<-SHELL
     debconf-set-selections <<< 'mysql-server mysql-server/root_password password password'
     debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password password'
     apt-get update
     apt-get upgrade -y
     apt-get install -y mysql-server mysql-client golang gcc electric-fence git
     chmod +x /vagrant/Setting_Up_Cross_Compilers.sh
     /vagrant/Setting_Up_Cross_Compilers.sh
   SHELL
end
