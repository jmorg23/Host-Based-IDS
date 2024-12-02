package com.IDS_MAIN;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class IDS {

    private static Map<String, Integer> ipPacketCount = new HashMap<>();
    private static final int PACKET_RATE = 1000; // more than 1000 packets in 1 second will be considered DOS
                                                           // attack
    private static final int SYN_FLOOD = 1000; // Number of SYN packets from a single IP in a short period
    private static long lastTimestamp = System.currentTimeMillis();
    private static boolean showIncomingPackets = false;
    // set of known malicious file signitures
    private static HashMap<String, String> knownMaliciousSignatures = new HashMap<>();


    // track download of executables
    private static int exeFileDownloadThreshold = 10;
    private static int exeFileDownloadCount = 0;

    static {
        // Add known malicious file hashes
        knownMaliciousSignatures.put("49cd7d9f6d9096e25cf5a95c17b17c8a", "disables Windows Defender features");
        knownMaliciousSignatures.put("faecb8128727e4d7b36e49b3161a2c9e",
                "Manipulates User Authorization as well as change/create files");
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException {

        // Select what network interface to listen from
        PcapNetworkInterface device = new NifSelector().selectNetworkInterface();

        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        Scanner s = new Scanner(System.in);
        System.out.print("Would you like to see incomming packets: ");
        showIncomingPackets = s.nextLine().equals("yes");
        s.close();

        int byteLength = 65536; // in bytes
        int timeout = 50; // in milliseconds
        final PcapHandle handle = device.openLive(byteLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                timeout);
        PcapDumper dumper = handle.dumpOpen("out.pcap");

        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                if (showIncomingPackets) {
                    System.out.println(packet);
                }
                // Check for packet rate, for dos attacks
                long currentTimestamp = System.currentTimeMillis();
                if (currentTimestamp - lastTimestamp < 1000) { // 1 second time window
                    ipPacketCount.merge(packet.getClass().getName(), 1, Integer::sum);
                    if (ipPacketCount.get(packet.getClass().getName()) > PACKET_RATE) {
                        System.out.println("Potential DoS attack detected (High packet rate of same packet type)!");
                    }
                } else {
                    ipPacketCount.clear();
                    lastTimestamp = currentTimestamp;
                }

                byte[] rawData = packet.getRawData();

                if (rawData != null && rawData.length > 0) {
                    // Check for SYN flag in the TCP header (TCP header starts after the Ethernet
                    // header)
                    if (rawData.length >= 54) {
                        byte tcpFlags = rawData[47 + 13]; // 47 is the start of the TCP header in the packet

                        if ((tcpFlags & 0x02) != 0) { // Check if SYN
                            String srcIp = getIp(rawData); // get source IP
                            // track the number of SYN packets that are coming from the same source Ip
                            ipPacketCount.put(srcIp, ipPacketCount.getOrDefault(srcIp, 0) + 1);
                            if (ipPacketCount.get(srcIp) > SYN_FLOOD) {
                                System.out.println("SYN flood detected from IP: " + srcIp);
                            }
                        }
                    }

                    // detect suspicious behavior based on file type
                    heuristicCheck(rawData, packet.toString());

                    // Signature-based check
                    if (checkMaliciousFile(rawData)) {
                        System.out.println("Malicious file detected based on signature!");
                    }

                    // detect unusual file activity
                    String fileExtension = packet.toString().split("\\.")[1]; // check file extension

                    if (checkAnomalousActivity(fileExtension)) {
                        System.out.println("Anomalous file activity detected!");
                    }

                }

                try {
                    dumper.dump(packet, handle.getTimestamp());
                } catch (NotOpenException e) {
                    e.printStackTrace();
                }
            }
        };

        try {
            handle.loop(-1, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Print out handle statistics
        PcapStat stats = handle.getStats();
        System.out.println("Packets received: " + stats.getNumPacketsReceived());
        System.out.println("Packets dropped: " + stats.getNumPacketsDropped());
        System.out.println("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());
        System.out.println("Packets captured: " + stats.getNumPacketsCaptured());
        
        dumper.close();
        handle.close();
    }

    private static String getIp(byte[] rawData) {
        int ipStartIndex = 26; // IP header starts at byte 26
        int ip1 = rawData[ipStartIndex] & 0xFF;
        int ip2 = rawData[ipStartIndex + 1] & 0xFF;
        int ip3 = rawData[ipStartIndex + 2] & 0xFF;
        int ip4 = rawData[ipStartIndex + 3] & 0xFF;
        return ip1 + "." + ip2 + "." + ip3 + "." + ip4;
    }

    // check file against known malicious signatures
    private static boolean checkMaliciousFile(byte[] fileData) {
        String fileHash = generateFileHash(fileData);
        return knownMaliciousSignatures.containsKey(fileHash);
    }

    private static String generateFileHash(byte[] fileData) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(fileData);
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(Integer.toHexString(0xFF & b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "";
        }
    }

    // Heuristic-based detection (check for suspicious file types or sizes)
    private static void heuristicCheck(byte[] fileData, String fileName) {

        if (fileName.endsWith(".exe")) {
            System.out.println("Is part of a .exe file, could be malicous if not downloaded on purpose");
        } else if (fileName.endsWith(".bat")) {
            System.out.println("Is part of a .bat file, could be malicous if not downloaded on purpose");
        }

        if (fileData.length < 10 || fileData.length > 5000000) {
            System.out.println("unusual packet length...");
        }
    }

    // Anomaly-based detection (check for abnormal file download activity)
    private static boolean checkAnomalousActivity(String fileExtension) {
        if (fileExtension.equalsIgnoreCase("exe")) {
            exeFileDownloadCount++;
            if (exeFileDownloadCount > exeFileDownloadThreshold) {
                return true; // Too many executable files detected
            }
        }
        return false;
    }


}
