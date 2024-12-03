package com.IDS_MAIN;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.io.IOException;

import java.sql.Timestamp;

import java.util.Scanner;

public class IDS {

    private static boolean showIncomingPackets = false;
    private static boolean breakLoop = false;

    public static void main(String[] args)
            throws PcapNativeException, NotOpenException, IOException, InterruptedException {

        // Select what network interface to listen from
        PcapNetworkInterface device = getNetworkInterface();

        Scanner s = new Scanner(System.in);
        System.out.print("Would you like to see incomming packets: ");
        showIncomingPackets = s.nextLine().equals("yes");

        int byteLength = 65536; // in bytes
        int timeout = 50; // in milliseconds
        final PcapHandle handle = device.openLive(byteLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                timeout);
        final PcapDumper dumper = handle.dumpOpen("out.pcap");

        final Listener myListener = initListener(handle);
        checkQuit(s);
        while (true) {
            final Packet curPacket = myListener.getNextPacket();
            if (showIncomingPackets) {
                System.out.println(curPacket);
            }
            new PacketInspecter(curPacket).start();

            dumpPacket(curPacket, dumper, handle);

            if (breakLoop) {
                handle.breakLoop();
                break;
            }
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

    public static void checkQuit(Scanner s) {
        new Thread(() -> {
            while (true)
                if (s.nextLine().contains("q")) {
                    breakLoop = true;
                    break;
                }

        }).start();
    }

    public static void dumpPacket(Packet packet, PcapDumper dumper, PcapHandle handle) {
        new Thread(() -> {
            try {
                Timestamp t;
                if((t = handle.getTimestamp()) != null)
                dumper.dump(packet, t);
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(0);
            }
        }).start();
    }

    public static Listener initListener(PcapHandle handle) throws PcapNativeException, NotOpenException {
        Listener listener = new Listener(handle);
        listener.startListener();
        return listener;
    }

    public static PcapNetworkInterface getNetworkInterface() throws IOException {

        PcapNetworkInterface device;
        while ((device = new NifSelector().selectNetworkInterface()) == null);

        return device;
    }

}
