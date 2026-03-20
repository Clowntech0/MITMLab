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


//        try{
//            test();
//        } catch(Exception e){
//            System.exit(2);
//        }

        PcapNetworkInterface networkInterface;
        try {
            networkInterface = MacAddressResolver.getAvailableNetworkInterface();
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        posionICMP(networkInterface);

        System.exit(2);

        PcapHandle handle;
        try {
            handle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        byte[] payload = new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};
        IcmpV4EchoReplyPacket.Builder icmpBuilder = new IcmpV4EchoReplyPacket.Builder();
        icmpBuilder
                .identifier((short) 12345)
                .sequenceNumber((short) 1)
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload)).build();

        Packet icmpPacket = icmpBuilder.build();
        //System.out.println(icmpPacket);


        String strSrcIpAddress = "192.168.0.171";
        String strDstIpAddress = "192.168.0.118";

        MacAddress strDstMacAddress = null;
        try {
            strDstMacAddress = MacAddressResolver.resolveMacAddress(InetAddress.getByName(strDstIpAddress));
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }

        byte[] echoData = new byte[4000 - 28];
        for (int i = 0; i < echoData.length; i++) {
            echoData[i] = (byte) i;
        }

        IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();
        echoBuilder
                .identifier((short) 1)
                .payloadBuilder(new UnknownPacket.Builder().rawData(echoData));

        IcmpV4CommonPacket.Builder icmpV4CommonBuilder = new IcmpV4CommonPacket.Builder();
        icmpV4CommonBuilder
                .type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(echoBuilder)
                .correctChecksumAtBuild(true);

        IpV4Packet.Builder ipV4Builder = new IpV4Packet.Builder();
        try {
            ipV4Builder
                    .version(IpVersion.IPV4)
                    .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                    .ttl((byte) 100)
                    .protocol(IpNumber.ICMPV4)
                    .srcAddr((Inet4Address) InetAddress.getByName(strSrcIpAddress))
                    .dstAddr((Inet4Address) InetAddress.getByName(strDstIpAddress))
                    .payloadBuilder(icmpV4CommonBuilder)
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);
        } catch (UnknownHostException e1) {
            throw new IllegalArgumentException(e1);
        }

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        MacAddress srcMacAddr = MacAddress.getByAddress(networkInterface.getLinkLayerAddresses().getFirst().getAddress());
        etherBuilder
                .dstAddr(strDstMacAddress)
                .srcAddr(srcMacAddr)
                .type(EtherType.IPV4)
                .paddingAtBuild(true);

        for (int i = 0; i < 1; i++) {
            echoBuilder.sequenceNumber((short) i);
            ipV4Builder.identification((short) i);

            for (final Packet ipV4Packet : IpV4Helper.fragment(ipV4Builder.build(), 1403)) {
                etherBuilder.payloadBuilder(
                        new AbstractPacket.AbstractBuilder() {
                            @Override
                            public Packet build() {
                                return ipV4Packet;
                            }
                        });

                Packet p = etherBuilder.build();

                System.out.println(p);
                try {
                    handle.sendPacket(p);
                } catch (PcapNativeException ex) {
                    throw new RuntimeException(ex);
                } catch (NotOpenException ex) {
                    throw new RuntimeException(ex);
                }

                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    break;
                }
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                break;
            }
        }

        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException noe) {
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
            }
            handle.close();
        }
    }

    public static void posionICMP(PcapNetworkInterface networkInterface){

        int capturedICMPPackets = 0;

        if (networkInterface == null){
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

        while(capturedICMPPackets < 10){

            try {
                Packet packet = null;
                packet = handle.getNextPacketEx();

                if(packet.contains(IcmpV4EchoPacket.class)){
                    IcmpV4EchoPacket icmpV4EchoPacket = packet.get(IcmpV4EchoPacket.class);

                    System.out.println(icmpV4EchoPacket);


                    capturedICMPPackets++;
                }


            } catch (NotOpenException e) {
                e.printStackTrace();
            } catch (EOFException e) {
                e.printStackTrace();
            } catch (PcapNativeException e) {
                e.printStackTrace();
            } catch (TimeoutException e) {
                continue;
            }
        }
    }

    private static void test() throws Exception {
        // Pick interface: either pass interface name as first arg or use first available

        PcapNetworkInterface nif = null;
        try {
            nif = MacAddressResolver.getAvailableNetworkInterface();
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

        System.out.println("Using interface: " + nif.getName() + " (" + nif.getDescription() + ")");

        // Open handle: 10 ms timeout (used by getNextPacketEx to trigger TimeoutException)
        PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        // Set a BPF filter for ICMP only
        handle.setFilter("icmp", BpfProgram.BpfCompileMode.OPTIMIZE);

        int capturedICMPPackets = 0;
        int target = 10;

        try {
            while (capturedICMPPackets < target) {
                try {
                    // Blocks until a packet arrives or the handle timeout is reached
                    Packet packet = handle.getNextPacketEx(); // will NOT return null

                    // Check for an ICMPv4 Echo (ping) inside the packet
                    if (packet.contains(IcmpV4EchoPacket.class)) {
                        IcmpV4EchoPacket icmpEcho = packet.get(IcmpV4EchoPacket.class);
                        System.out.println("Captured ICMPv4 Echo packet: " + icmpEcho);
                        capturedICMPPackets++;
                    } else {
                        // If you want to inspect other ICMP types:
                        // if (packet.contains(IcmpV4CommonPacket.class)) { ... }
                    }

                } catch (TimeoutException te) {
                    // No packet within the handle timeout; continue listening
                } catch (NotOpenException | PcapNativeException e) {
                    // Underlying error — print and break (or handle differently)
                    e.printStackTrace();
                    break;
                }
            }
        } finally {
            handle.close();
            System.out.println("Handle closed, captured " + capturedICMPPackets + " packets.");
        }
    }

    private static class icmpEchoListen implements Callable<MacAddress> {

        private final PcapHandle handle;
        private final InetAddress targetIPAddress;

        private icmpEchoListen(PcapHandle handle, InetAddress targetIPAddress) {
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





//PacketListener listener = packet -> {
//            if (packet.contains(IcmpV4EchoPacket.class)) {
//
//                IcmpV4EchoPacket icmpV4EchoPacket = packet.get(IcmpV4EchoPacket.class);
//                IcmpV4EchoPacket.IcmpV4EchoHeader icmpV4EchoHeader = icmpV4EchoPacket.getHeader();
//
//                icmpV4EchoHeader.getSequenceNumber();
//
//                IcmpV4EchoReplyPacket.Builder icmpReplyBuilder = new IcmpV4EchoReplyPacket.Builder();
////
////                byte[] payload = new byte[] { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04 };
////                IcmpV4EchoReplyPacket.Builder icmpBuilder = new IcmpV4EchoReplyPacket.Builder();
////                icmpBuilder
////                        .identifier((short) 12345)
////                        .sequenceNumber((short) 1)
////                        .payloadBuilder(new UnknownPacket.Builder().rawData(payload)).build();
////
////                Packet icmpPacket = icmpBuilder.build();
////                System.out.println(icmpPacket);
//            }
//        };
//    }
//}