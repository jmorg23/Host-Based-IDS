package com.companyname.appname;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.List;

public class Test{

    public static void main(String[] args) {
        try {
            // Step 1: Get a network interface
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
            if (devices.isEmpty()) {
                System.out.println("No devices found.");
                return;
            }

            System.out.println("Available Network Interfaces:");
            for (int i = 0; i < devices.size(); i++) {
                System.out.println(i + ": " + devices.get(i).getName() + " (" + devices.get(i).getDescription() + ")");
            }
            //PcapNetworkInterface nif = Pcaps.getDevByName("\\Device\\NPF_{115822A0-0CF9-43BF-8AA3-42D1ECDFA78B}"); // Replace with your interface name

            // Select the first device (or allow user to choose)
            PcapNetworkInterface device = Pcaps.getDevByName("\\Device\\NPF_{115822A0-0CF9-43BF-8AA3-42D1ECDFA78B}"); // Change to user input if needed
            System.out.println("Using device: " + device.getName());

            // Step 2: Open the device for capturing
            int snapshotLength = 65536; // Maximum capture size
            int timeout = 50;           // Timeout in milliseconds
            PcapHandle handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

            System.out.println("Starting packet capture...");
            handle.loop(-1, (PacketListener)packet -> processPacket(packet));

            // Close the handle after the capture is done
            handle.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Process and log the packet data
    private static void processPacket(Packet packet) {
        System.out.println("Captured a packet: [data (" + packet.length() + " bytes)]");

        // Convert to hex stream
        String hexStream = bytesToHex(packet.getRawData());
        System.out.println("  Hex stream: " + hexStream);

            if (packet.contains(IpV4Packet.class)) {
        IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
        System.out.println("IPv4 Packet: " + ipv4Packet);
    } else if (packet.contains(IpV6Packet.class)) {
        IpV6Packet ipv6Packet = packet.get(IpV6Packet.class);
        System.out.println("IPv6 Packet: " + ipv6Packet);
    } else if (packet.contains(TcpPacket.class)) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        System.out.println("TCP Packet: " + tcpPacket);
    } else {
        System.out.println("Unknown Packet");
    }
        // Identify the packet type (custom logic for UnknownPacket example)
        if (isUnknownPacket(packet)) {
            System.out.println("Unknown Packet Type: UnknownPacket");
        } else {
            System.out.println("Identified Packet: " + packet.getClass().getSimpleName());
        }
    }

    // Helper function to check if the packet is "unknown"
    private static boolean isUnknownPacket(Packet packet) {
        // Example logic: Check if packet is empty or unknown type
        return packet == null || packet.getRawData().length == 0;
    }

    // Helper function to convert bytes to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x ", b));
        }
        return hexString.toString().trim();
    }
}

