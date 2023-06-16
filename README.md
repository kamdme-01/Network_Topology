# Network Topology

This is an application that automatically lists the topology of a network from the host machine, the program will use the SNPM protocol to obtain information on routers.

## How to use it ?

Basically, the application will start from the address of the first router with DHCP. Then, it will find recursively all connected routers and interfaces
of the autonomous system area thanks to the routing tables. And so on, until it found every routers of the AS.

## Installation of the libraries

#### 1. GNS3 project
In first, you need to import the GNS3 project, can be found at https://home.zcu.cz/~maxmilio/PSI/psi-example-project-1.gns3project.
You can also create your personal GNS3 project and use this application on it, but you have to configure it as well.

#### 2. Activate SNMP server on router

After downloading and installing the GNS3 project, you will have to activate the SNMP on the router by sending theses commands in the console :
```shell
enable
config terminal
snmp-server community public ro
end
write
```

Then, we need to configure the project and install all the necessary libraries.

```shell
apt-get install nano
apt-get install python3-pip
pip3 install scapy pysnmp
pip3 install colorama

pip3 uninstall pyasn1
pip3 install pyasn1==0.4.8
```

## Launch the application

- You  have to import the python code by creating a python file with nano for example or use clone the repository.
```
git clone https://github.com/kamdme-01/Network_Topology.git
```
- By using nano, you just have to create a file by using the command :
```
nano run.py
```
- Paste the code you can get from the file run.py in this repository and save the file with 'CTRL + X' ad 'Y' and 'ENTER'
- Then, start the python application by start the following command:
```
python3 run.py
```
- Wait until the information's list appears.
-----