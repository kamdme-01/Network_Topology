from pysnmp.hlapi import *
from scapy.all import *

def get_initial_dhcp_router():
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr="ff:ff:ff:ff:ff:ff") / DHCP(options=[("message-type", "discover"), "end"])

    # Send DHCP discover packet and capture the response
    dhcp_offer = srp1(dhcp_discover, verbose=False)

    # Extract the initial DHCP router IP from the response
    if dhcp_offer and DHCP in dhcp_offer:
        for option in dhcp_offer[DHCP].options:
            print('*')
            if option[0] == "router":
                return option[1]

    return None

# Function to retrieve routing table information using SNMP
def get_routing_table(router_ip):
    community_string = 'public'  # Replace with your SNMP community string
    snmp_object = ObjectIdentity('SNMPv2-MIB', 'ipRouteTable')
    
    iterator = getCmd(SnmpEngine(),
                      CommunityData(community_string),
                      UdpTransportTarget((router_ip, 161)),
                      ContextData(),
                      ObjectType(snmp_object),
                      lexicographicMode=False)

    # Iterate over SNMP response and retrieve routing table entries
    routing_table = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in iterator:
        if errorIndication:
            print(f"Error: {errorIndication}")
            break
        elif errorStatus:
            print(f"Error: {errorStatus}")
            break
        else:
            for varBind in varBinds:
                oid, value = varBind
                routing_table.append(value)

    return routing_table


# Recursive function to discover routers in the network
def discover_routers(router_ip):
    print(f"Discovering router at {router_ip}")
    routing_table = get_routing_table(router_ip)

    for entry in routing_table:
        next_hop = entry['ipRouteNextHop']
        if next_hop != '0.0.0.0':
            discover_routers(next_hop)


# Main function to start the topology discovery
def main():
    print("starting main")
    dhcp_router_ip =  get_initial_dhcp_router()
    if not dhcp_router_ip:
        return

    print("Starting network topology discovery...")
    discover_routers(dhcp_router_ip)
    print("Topology discovery complete!")


if __name__ == '__main__':
    main()
