package com.companyname.appname;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import com.sun.jna.Platform;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class Loop2 {

    private static Map<String, Integer> ipPacketCount = new HashMap<>();
    private static final int PACKET_RATE_THRESHOLD = 1000;  // Example: more than 1000 packets in 1 second
    private static final int SYN_FLOOD_THRESHOLD = 100; // Number of SYN packets from a single IP in a short period
    private static long lastTimestamp = System.currentTimeMillis();

    static PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        PcapNetworkInterface device = getNetworkDevice();
        System.out.println("You chose: " + device);

        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        int snapshotLength = 65536; // in bytes   
        int readTimeout = 50; // in milliseconds                   
        final PcapHandle handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        PcapDumper dumper = handle.dumpOpen("out.pcap");

        // Set a filter to only listen for TCP packets on port 25565 (e.g., Minecraft)
       // String filter = "tcp port 25565";
       // handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                // Check for packet rate (DoS Detection)
                long currentTimestamp = System.currentTimeMillis();
                if (currentTimestamp - lastTimestamp < 1000) { // 1 second time window
                    ipPacketCount.merge(packet.getClass().getName(), 1, Integer::sum);
                    if (ipPacketCount.get(packet.getClass().getName()) > PACKET_RATE_THRESHOLD) {
                        System.out.println("Potential DoS attack detected (High packet rate)!");
                    }
                } else {
                    ipPacketCount.clear();  // Reset counter after 1 second
                    lastTimestamp = currentTimestamp;
                }

                // Extract raw byte data and check for TCP SYN flood
                byte[] rawData = packet.getRawData();
                if (rawData != null && rawData.length > 0) {
                    // Example: Check for SYN flag in the TCP header (TCP header starts after the Ethernet header)
                    if (rawData.length >= 54) {  // Assuming Ethernet header + IP header + TCP header
                        // TCP flags are typically at byte offset 47 and 48 (for Ethernet and IPv4)
                        byte tcpFlags = rawData[47 + 13];  // 47 is the start of the TCP header in the packet

                        // TCP flag checking for SYN flood (SYN flag is 0x02)
                        if ((tcpFlags & 0x02) != 0) {  // Check if SYN flag is set
                            String srcIp = getSourceIp(rawData);  // Extract source IP from raw data
                            //System.out.println("Potential SYN Flood detected from IP: " + srcIp);

                            // Track number of SYN packets from the same source IP
                            ipPacketCount.put(srcIp, ipPacketCount.getOrDefault(srcIp, 0) + 1);
                            if (ipPacketCount.get(srcIp) > SYN_FLOOD_THRESHOLD) {
                                System.out.println("SYN flood detected from IP: " + srcIp);
                            }
                        }
                    }
                }

                // Dump packet to file
                try {
                    dumper.dump(packet, handle.getTimestamp());
                } catch (NotOpenException e) {
                    e.printStackTrace();
                }
            }
        };

        // Start packet capture loop
        try {
            int maxPackets = -1;
            handle.loop(maxPackets, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Print out handle statistics
        PcapStat stats = handle.getStats();
        System.out.println("Packets received: " + stats.getNumPacketsReceived());
        System.out.println("Packets dropped: " + stats.getNumPacketsDropped());
        System.out.println("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());
        if (Platform.isWindows()) {
            System.out.println("Packets captured: " + stats.getNumPacketsCaptured());
        }

        // Cleanup when complete
        dumper.close();
        handle.close();
    }

    // Utility method to extract source IP address from raw data
    private static String getSourceIp(byte[] rawData) {
        // Assuming Ethernet frame + IPv4 header: IP source address starts at byte 26 (IPv4 header starts at byte 14)
        int ipStartIndex = 26; 
        int ip1 = rawData[ipStartIndex] & 0xFF;
        int ip2 = rawData[ipStartIndex + 1] & 0xFF;
        int ip3 = rawData[ipStartIndex + 2] & 0xFF;
        int ip4 = rawData[ipStartIndex + 3] & 0xFF;
        return ip1 + "." + ip2 + "." + ip3 + "." + ip4;
    }
}
