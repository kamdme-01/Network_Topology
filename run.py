from pysnmp.hlapi import *
from scapy.all import *
from pysnmp.smi import builder, view
from scapy.config import conf

conf.checkIPaddr = False


# Load MIB files
mib_builder = builder.MibBuilder().loadModules(
    'SNMPv2-MIB', 'IP-MIB'
)
mib_view_controller = view.MibViewController(mib_builder)

# Function to retrieve routing table information using SNMP
def get_routing_table(router_ip):
    community_string = 'public' 
    snmp_object = ObjectType(ObjectIdentity('IP-MIB', 'ipRouteTable')).addAsn1MibSource('file:///usr/share/snmp/mibs')

    iterator = getCmd(SnmpEngine(),
                      CommunityData(community_string),
                      UdpTransportTarget((router_ip, 161)),
                      ContextData(),
                      snmp_object,
                      lexicographicMode=False,
                      lookupNames=True,
                      lookupValues=True)

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
