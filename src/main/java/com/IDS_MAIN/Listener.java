package com.IDS_MAIN;

import java.util.LinkedList;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;

public class Listener {


    private Listen listen;

    public Listener(PcapHandle handle){
        listen = new Listen(handle);
    }

    public Packet getNextPacket() throws InterruptedException{
        while(listen.packets.isEmpty()){
            Thread.sleep(10);
        }        
        return listen.packets.removeFirst();
    }

    
    public void startListener(){
        listen.start();
    }

    public class Listen extends Thread{

        public LinkedList<Packet> packets = new LinkedList<>();
        private PcapHandle handle;
        
        public Listen(PcapHandle handle){
            this.handle = handle;
        }    
        public void run(){
            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    packets.add(packet);
                }
            };
            try {
                handle.loop(-1, listener);
            } catch (Exception e){
            }

        }
    }
}

