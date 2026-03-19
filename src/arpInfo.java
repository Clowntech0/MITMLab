import org.pcap4j.util.MacAddress;

import java.net.InetAddress;

//struct for holding info about resolved ARP requests
public record arpInfo(InetAddress ipAddress, MacAddress macAddress){ }
