import java.net.Inet4Address;
import java.util.List;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

public class main {

    public static void main(String[] args) throws Exception {
        // 1. Find a suitable network interface (NIF)
        // You may need to select a specific NIF based on your system
        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
        PcapNetworkInterface nif = null;
        for (PcapNetworkInterface tempNif : nifs) {
            // Find the first non-loopback interface with an IPv4 address
            if (!tempNif.isLoopBack() && !tempNif.getAddresses().isEmpty()) {
                nif = tempNif;
                break;
            }
        }

        if (nif == null) {
            System.out.println("No suitable network interface found. Exiting.");
            return;
        }

        System.out.println("Using NIF: " + nif.getName() + " (" + nif.getDescription() + ")");

        // 2. Open a pcap handle
        int snapLen = 65536; // Snapshot length (bytes)
        PromiscuousMode mode = PromiscuousMode.PROMISCUOUS; // Promiscuous mode
        int timeout = 10; // Timeout (milliseconds)

        // The handle provides the API for capturing and sending packets
        PcapHandle handle = nif.openLive(snapLen, mode, timeout);

        // 3. Capture a single packet
        try {
            Packet packet = handle.getNextPacketEx();
            System.out.println("Captured packet: " + packet);

            // 4. Get packet information (example: source IPv4 address)
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            if (ipV4Packet != null) {
                Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
                System.out.println("Source Address: " + srcAddr.getHostAddress());
            }

        } catch (Exception e) {
            System.out.println("An exception occurred while capturing packets: " + e.getMessage());
        } finally {
            // 5. Close the handle
            handle.close();
        }
    }
}
