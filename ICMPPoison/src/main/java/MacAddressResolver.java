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
import java.util.concurrent.*;

public class MacAddressResolver {

    private static MacAddress resolvedMacAddress;


    public static MacAddress resolveMacAddress(InetAddress ipAddress) {

        PcapNetworkInterface networkInterface;

        final MacAddress resolvedAddress = null;

        try {
            networkInterface = getAvailableNetworkInterface();
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        if (networkInterface == null){
            return null;
        }

        PcapHandle handle = null;
        PcapHandle sendHandle = null;
        try {
            handle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            sendHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<MacAddress> future = pool.submit(new ARPReplyListen(handle, ipAddress));

        MacAddress sourceMac = MacAddress.getByAddress(networkInterface.getLinkLayerAddresses().getFirst().getAddress());
        MacAddress destinationMac = MacAddress.getByName("ff:ff:ff:ff:ff:ff");

        InetAddress sourceIP = null;
        InetAddress destinationIP = null;
        try {
            sourceIP = InetAddress.getByAddress(networkInterface.getAddresses().getFirst().getAddress().getAddress());
            destinationIP = InetAddress.getByAddress(ipAddress.getAddress());
        } catch (UnknownHostException e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }



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

        try {
            sendHandle.sendPacket(requestPacket);
        } catch (NotOpenException e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        try {
            resolvedMacAddress = future.get(10, TimeUnit.SECONDS);
        } catch (TimeoutException | InterruptedException | ExecutionException e){
            e.printStackTrace();
        } finally {
            pool.shutdown();
        }


        return resolvedMacAddress;
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
                    return nInterface;
                }
            }
        }
        return null;
    }

    private static class ARPReplyListen implements Callable<MacAddress>{

        private final PcapHandle handle;
        private final InetAddress targetIPAddress;

        private ARPReplyListen(PcapHandle handle, InetAddress targetIPAddress) {
            this.handle = handle;
            this.targetIPAddress = targetIPAddress;
        }

        @Override
        public MacAddress call() throws Exception {
            while (!Thread.currentThread().isInterrupted()) {
                Packet packet = handle.getNextPacket();
                if(packet == null){
                    continue;
                }

                ArpPacket arpPacket = packet.get(ArpPacket.class);
                if(arpPacket != null && arpPacket.getHeader().getOperation().equals(ArpOperation.REPLY)){
                    ArpPacket.ArpHeader arpHeader = arpPacket.getHeader();
                    if(targetIPAddress.equals(arpHeader.getSrcProtocolAddr())) {
                        return arpHeader.getSrcHardwareAddr();
                    }
                }
            }
            return null;
        }
    }
}


