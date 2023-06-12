from pysnmp.hlapi import *
from scapy.all import *

def get_routing_table(router_ip):
    routing_table = []

    # SNMP Object Identifiers (OIDs) for routing table information
    oid_route_index = '1.3.6.1.2.1.4.21.1.1'  # IP Route Index
    oid_route_dest = '1.3.6.1.2.1.4.21.1.1'  # IP Route Destination
    oid_route_nexthop = '1.3.6.1.2.1.4.21.1.7'  # IP Route Next Hop

    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData('public'),  # SNMP community string
        UdpTransportTarget((router_ip, 161)),  # Router IP address and SNMP port
        ContextData(),
        ObjectType(ObjectIdentity(oid_route_index)),
        ObjectType(ObjectIdentity(oid_route_dest)),
        ObjectType(ObjectIdentity(oid_route_nexthop)),
        lexicographicMode=False
    ):
        if errorIndication:
            print(f"SNMP query error: {errorIndication}")
            break
        elif errorStatus:
            print(f"SNMP query error: {errorStatus}")
            break
        else:
            for varBind in varBinds:
                route_index = varBind[0][1]
                route_dest = varBind[1][1].prettyPrint()
                route_nexthop = varBind[2][1].prettyPrint()

                route_info = {
                    'index': route_index,
                    'destination': route_dest,
                    'next_hop': route_nexthop
                }

                routing_table.append(route_info)

    return routing_table


def discover_topology(router_ip, community):
    # Retrieve the routing table from the router
    routing_table = get_routing_table(router_ip)

    print("*"*53)
    print(f"This is the topology from: {router_ip}")

    for route in routing_table:
        route_dest = route['destination']
        route_next_hop = route['next_hop']

        # Print the current interface
        print(f"Interface: {route_dest}")

        # Recursively discover the topology for the next hop if it exists
        if route_next_hop != '0.0.0.0':
            discover_topology(route_next_hop, community)


def get_router_ip_via_dhcp():
    conf.checkIPaddr = False
    packet_dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr="ff:ff:ff:ff:ff:ff") / DHCP(options=[("message-type", "discover"), "end"])
    packet_dhcp_offer = srp1(packet_dhcp_discover, verbose=0)

    if packet_dhcp_offer and DHCP in packet_dhcp_offer and packet_dhcp_offer[DHCP].options[0][1] == 2: # 2 == type Offer packet
        return get_option(packet_dhcp_offer[DHCP].options, 'router')
    else:
        return None

def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    for option, value in dhcp_options:
        if option == key:
            if isinstance(value, bytes):
                if key in must_decode:
                    return value.decode()
                else:
                    return value
            else:
                return value

def main():
    router_ip = get_router_ip_via_dhcp()
    if router_ip:
        community = 'public'  # SNMP community string
        discover_topology(router_ip, community)
    else:
        print("Failed to retrieve the initial router IP via DHCP.")

if __name__ == '__main__':
    main()
