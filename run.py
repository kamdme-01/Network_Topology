from builtins import print
from pysnmp.hlapi import *
from pysnmp.smi import builder, view
from scapy.config import conf
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp1

def discover_topology(host, community):
    notFound = 'No more variables left in this MIB View'
    oid_interfaces = '1.3.6.1.2.1.4.20.1.1'
    oid_next_hop = '1.3.6.1.2.1.4.24.4.1.4'

    print("====================================================")
    print(f"This is the topology from: {host}")
    print("====================================================")

    next_hop = ''
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(),
                                                                        CommunityData(community),
                                                                        UdpTransportTarget((host, 161)),
                                                                        ContextData(),
                                                                        ObjectType(ObjectIdentity(oid_interfaces)),
                                                                        ObjectType(ObjectIdentity(oid_next_hop)),
                                                                        lexicographicMode=False):
        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print(f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
            break
        else:
            for varBind in varBinds:
                oid, value = varBind
                if ('0.0.0.0' in value.prettyPrint()) or value.prettyPrint() == notFound:
                    continue

                if oid_interfaces in str(oid):
                    print(f'Interface: {value.prettyPrint()}')

                if oid_next_hop in str(oid):
                    next_hop = value.prettyPrint()

    if next_hop:
        print(f'NextHop IP address is: {next_hop}')
        discover_topology(next_hop, community)
    else:
        print('No NextHop IP address found')

def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass

conf.checkIPaddr = False
packet_dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr="ff:ff:ff:ff:ff:ff") / DHCP(options=[("message-type", "discover"), "end"])
packet_dhcp_offer = srp1(packet_dhcp_discover, verbose=0)

if packet_dhcp_offer and DHCP in packet_dhcp_offer and packet_dhcp_offer[DHCP].options[0][1] == 2:
    community = 'public'
    router_ip =  get_option(packet_dhcp_offer[DHCP].options, 'router')
    discover_topology(router_ip, community)
else:
    print("Failed to retrieve the initial router IP via DHCP.")

