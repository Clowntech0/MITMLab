import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ARP {

    public static MacAddress LAST_RESOLVED_ADDRESS = null;

    public static MacAddress resolveMacFromIP(String ipAddress) throws UnknownHostException, PcapNativeException {
        return resolveMacFromIP(InetAddress.getByName(ipAddress));
    }
    public static MacAddress resolveMacFromIP(InetAddress ipAddress) throws PcapNativeException {

        PcapNetworkInterface networkInterface;

        final MacAddress resolvedAddress;

        try {
            networkInterface = getAvailableNetworkInterface();
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        if (networkInterface == null){
            return null;
        }

        PcapHandle handle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        PcapHandle sendHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        ExecutorService pool = Executors.newSingleThreadExecutor();

        try{
            MacAddress sourceMac = MacAddress.getByAddress(networkInterface.getLinkLayerAddresses().getFirst().getAddress());
            MacAddress destinationMac = MacAddress.getByName("ff:ff:ff:ff:ff:ff");

            InetAddress sourceIP = InetAddress.getByAddress(networkInterface.getAddresses().getFirst().getAddress().getAddress());
            InetAddress destinationIP = InetAddress.getByAddress(ipAddress.getAddress());

            ArpPacket.Builder arpRequest = new ArpPacket.Builder();

            arpRequest
                    .hardwareType(ArpHardwareType.ETHERNET)
                    .protocolType(EtherType.IPV4)
                    .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                    .protocolAddrLength((byte) sourceIP.getAddress().length)
                    .operation(ArpOperation.REQUEST)
                    .srcHardwareAddr(sourceMac)
                    .srcProtocolAddr(sourceIP)
                    .dstHardwareAddr(destinationMac)
                    .dstProtocolAddr(destinationIP);

            EthernetPacket.Builder requestHeader = new EthernetPacket.Builder();

            requestHeader
                    .dstAddr(destinationMac)
                    .srcAddr(sourceMac)
                    .type(EtherType.ARP)
                    .payloadBuilder(arpRequest)
                    .paddingAtBuild(true);

            Packet requestPacket = requestHeader.build();

            System.out.println(requestPacket);

            sendHandle.sendPacket(requestPacket);

            handle.setFilter(
                    "arp and src host "
                            + destinationIP.getHostAddress()
                            + " and dst host "
                            + sourceIP.getHostAddress()
                            + " and ether dst "
                            + Pcaps.toBpfString(sourceMac),
                    BpfProgram.BpfCompileMode.OPTIMIZE);

            Packet arpReply = handle.getNextPacket();

            if (arpReply != null && arpReply.contains(ArpPacket.class)) {
                ArpPacket arpPacket = arpReply.get(ArpPacket.class);
                if (arpPacket.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                    System.out.println("Received ARP Reply: " + arpPacket.getHeader().getSrcHardwareAddr());
                }
            } else {
                System.out.println("No reply received.");
            }

            arpInfo arpReplyInfo = new arpInfo(InetAddress.getByName("192.168.12.12"), MacAddress.getByName("14-c6-7d-d4-a7-7d"));
            PacketListener listener = new arpPacketListener(arpReplyInfo);

            PacketListener packetListener =
                    packet -> {
                        if (packet.contains(ArpPacket.class)) {
                            ArpPacket arp = packet.get(ArpPacket.class);
                            if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                                System.out.println(arp.getHeader().getSrcHardwareAddr());
                                ARP.LAST_RESOLVED_ADDRESS = arp.getHeader().getSrcHardwareAddr();
                            }
                        }
                        System.out.println(packet);
                    };

            System.out.println(arpReplyInfo);

            try{
                handle.loop(10, packetListener);
            } catch (NotOpenException e) {
                throw new RuntimeException(e);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }


            handle.close();
            sendHandle.close();
            pool.shutdown();
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
            if (sendHandle != null && sendHandle.isOpen()) {
                sendHandle.close();
            }
            if (pool != null && !pool.isShutdown()) {
                pool.shutdown();
            }

        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        } catch (NotOpenException e) {
            throw new RuntimeException(e);
        } finally {
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
            if (sendHandle != null && sendHandle.isOpen()) {
                sendHandle.close();
            }
            if (pool != null && !pool.isShutdown()) {
                pool.shutdown();
            }
        }

        return ARP.LAST_RESOLVED_ADDRESS;
    }

    public static PcapNetworkInterface getAvailableNetworkInterface() throws PcapNativeException {
        List<PcapNetworkInterface> networkInterfaces = Pcaps.findAllDevs();

        //Find the first available interface with a valid ipv4 address
        for (PcapNetworkInterface nInterface : networkInterfaces){
            for(PcapAddress address : nInterface.getAddresses()){

                //find our ipv4 address
                if(address instanceof PcapIpV4Address){

                    //we dont want our loopback address
                    if(address.getAddress().isLoopbackAddress()){
                        continue;
                    }

                    System.out.println("IP4 Address found:");
                    System.out.println(address.getAddress().getHostAddress());

                    return nInterface;
                }
            }
        }
        return null;
    }
}
