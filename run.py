from pysnmp.hlapi import *
from scapy.all import *
from pysnmp.smi import builder, view
from scapy.config import conf

conf.checkIPaddr = False

from pysnmp.smi import builder, view

# Create a new MIB builder
mibBuilder = builder.MibBuilder()

# Load the default MIB sources
mibSources = mibBuilder.getMibSources()

# Get the MIB view
mibView = view.MibViewController(mibBuilder)

# Load required MIB modules
mibBuilder.loadModules('RFC1213-MIB')

# Get the OID for oid_interfaces
oid_interfaces = mibView.getNodeName('ipAdEntAddr')  # Replace with the appropriate MIB object name

# Get the OID for oid_next_hop
oid_next_hop = mibView.getNodeName('ipRouteNextHop')  # Replace with the appropriate MIB object name

# Print the OIDs
print(f"OID for oid_interfaces: {oid_interfaces}")
print(f"OID for oid_next_hop: {oid_next_hop}")



def get_initial_dhcp_router():
    print("starting method")
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
    community_string = 'public' 
    oid_interfaces = '1.3.6.1.2.1.4.20.1.1'

    
    iterator =  getCmd(SnmpEngine(),
                        CommunityData(community_string),
                        UdpTransportTarget((router_ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid_interfaces)),
                        ObjectType(ObjectIdentity(oid_next_hop)),
                        lookupNames=True,
                        lookupValues=True,
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
    routing_table = get_routing_table(router_ip, community)

    for entry in routing_table:
        if 'next_hop' in entry:
            next_hop = entry['next_hop']
            discover_routers(next_hop)
        else:
            print('No next hop found')
            

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
