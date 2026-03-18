import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

public class MITM{
    public static void main(String[] args) throws PcapNativeException, IOException {
        System.setProperty("jna.library.path", "C:/Windows/System32/Npcap/");

        List<PcapNetworkInterface> networkInterfaces = Pcaps.findAllDevs();

        for (PcapNetworkInterface nInterface : networkInterfaces){
            System.out.println(nInterface.getName() + " : " + nInterface.getAddresses());
        }
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        in.readLine();
    }
}