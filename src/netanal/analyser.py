def identify_protocol(packet: Packet) -> Protocol:
    if packet.haslayer(DNS):
        return Protocol.DNS

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.dport == Ports.HTTP or tcp_layer.sport == Ports.HTTP:
            return Protocol.HTTP
        if tcp_layer.dport == Ports.HTTPS or tcp_layer.sport == Ports.HTTPS:
            return Protocol.HTTPS
        return Protocol.TCP

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        if udp_layer.dport == Ports.DNS or udp_layer.sport == Ports.DNS:
            return Protocol.DNS
        return Protocol.UDP

    if packet.haslayer(ICMP):
        return Protocol.ICMP

    if packet.haslayer(ARP):
        return Protocol.ARP

    return Protocol.OTHER