from builtins import print
import colorama
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

    print(colorama.Back.WHITE + "                                                   " + colorama.Style.RESET_ALL)
    print(colorama.Fore.BLACK+colorama.Back.WHITE+f"This is the topology from : ({host}):"+colorama.Style.RESET_ALL)
    print(colorama.Back.WHITE + "                                                   " + colorama.Style.RESET_ALL)

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
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            for varBind in varBinds:
                oid, value = varBind
                #Continue if the oid is broadcast, and something we don't want, or no value in the result with this MIB oid.
                if ('0.0.0.0' in value.prettyPrint()) or value.prettyPrint() == notFound:
                    continue

                #Print the current intnerface
                if oid_interfaces in str(oid):
                    print(f'Interface : {value.prettyPrint()}')

                #Save the nextHop if there is one.
                if oid_next_hop in str(oid):
                    next_hop = value.prettyPrint()

    #Recursively method for nextHop if exist
    if next_hop:
        print(colorama.Fore.GREEN+f'NextHop IP address is : {next_hop}'+colorama.Style.RESET_ALL)
        discover_topology(next_hop, community)
    else:
        print(colorama.Fore.RED+'No NextHop IP address found'+colorama.Style.RESET_ALL)

# Function to extract dhcp_options by key
def get_option(dhcp_options, key):

    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass

# DHCP Part | Retrieve the IP address of the initial router
conf.checkIPaddr = False
packet_dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr="ff:ff:ff:ff:ff:ff") / DHCP(options=[("message-type", "discover"), "end"])
packet_dhcp_offer = srp1(packet_dhcp_discover, verbose=0)

if packet_dhcp_offer and DHCP in packet_dhcp_offer and packet_dhcp_offer[DHCP].options[0][1] == 2: #2 == type Offer packet
    community = 'public'  # SNMP community string
    router_ip =  get_option(packet_dhcp_offer[DHCP].options, 'router')
    discover_topology(router_ip, community)
else:
    print(colorama.Fore.RED+"Failed to retrieve the initial router IP via DHCP."+colorama.Style.RESET_ALL)