import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;

public class arpPacketListener implements PacketListener {

    private arpInfo packetInfo;

    public arpPacketListener(arpInfo returnInfo){
        packetInfo = returnInfo;
    }

    @Override
    public void gotPacket(Packet packet) {
        if (packet.contains(ArpPacket.class)) {
            ArpPacket arp = packet.get(ArpPacket.class);
            if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                System.out.println(arp.getHeader().getSrcHardwareAddr());

                packetInfo = new arpInfo(arp.getHeader().getSrcProtocolAddr(), arp.getHeader().getSrcHardwareAddr());
            }
        }
        System.out.println(packet);
    }
}
