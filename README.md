# Host-Based-IDS

This is a homeade Host-Based Intrusion Detection System(IDS)

# How to use:

* Make sure maven and java are all installed on your system as well as ncap https://npcap.com/
* Once the program is running, it will prompt you to enter a number representing one of the network interfaces to listen.(The interfaces are shown above)
* It will ask if you want to see incoming traffic. If “yes” then it will display all incoming traffic as it comes, else if not “yes” then it will not display packets.
* Now it will be checking each packet and letting you know if anything is out of the ordinary for that network interface.
* to cancel capture you can type q in the terminal to quit and view stats for that capture
* Also every packet for the current capture will be stored in the out.pcap file (can be viewed via wireshark).


# How it works:

This program works by capturing all incoming packets within the given network interface using Pcap4j an open source java API for capturing packets(https://github.com/kaitoy/pcap4j). Next it checks each packet for suspicious activity and also packet incoming rate. Packet rates that are abnormal will be deemed as a dos attack in which by default the program will print this warning message. This goes for a normal dos attack as well as syn flood attacks. It now also needs to check to see if any exe or bat files are being downloaded as this has a possibility of being malicious especially when the user is unaware of them being dowloaded. So either case the program will warn the user that they are being downloaded for further inspection(if desired by user). Next it will check for any of the incoming traffic to match known malicious software signatures. For this I just used two signatures for examples, others can be found at https://bazaar.abuse.ch/browse/. So now when a packet is incoming it will check its signature for anything similar to the two known signatures of malicious activity. Lastly it will check for a large amount of exe files being downloaded all at once or sequentially. If a lot of exe files are being downloaded it should be checked to see if the user is aware of this, as it is not a common thing to be happening. This is the essence of my IDS. It is made to check each incoming packet and warn the user of any potential malicious activity.

# Additional resources:
- https://npcap.com/ 
- https://github.com/qos-ch/slf4j
- https://slf4j.org/download.html
- https://github.com/kaitoy/pcap4j
- https://www.javadoc.io/doc/org.pcap4j/pcap4j/1.7.3/index.html
- https://stackoverflow.com/questions/46671308/how-to-create-a-java-maven-project-that-works-in-visual-studio-code
- https://www.devdungeon.com/content/packet-capturing-java-pcap4j
