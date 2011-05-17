package br.poli.ecomp.knocker;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Knocker {

	private static final long SEQ = 97730;// Math.abs(new Random().nextLong());

	private static Pcap pcap;

	private static byte[] remoteAddress;

	private static byte[] localAddress;

	private static int remotePort;

	private static int localPort;

	private final static String packetBytesString = "00304868 63d8001d 4ff9263a 08004500 00300423 40008006 fe54ac10 de68c8c4 a512042b 0050314e ff960000 00007002 4000156f 00000204 05b40101 0402";

	public static void main(String[] args) throws UnknownHostException {
		if (args.length != 3) {
			printUsage();
		} else {
			String remAd = args[0];
			remotePort = Integer.parseInt(args[1]);
			localPort = Integer.parseInt(args[2]);
			InetAddress address = InetAddress.getByName(remAd);
			remoteAddress = address.getAddress();

			System.out.println(remAd + " " + remotePort + " " + localPort);

			List<PcapIf> alldevs = new ArrayList<PcapIf>();
			StringBuilder errbuf = new StringBuilder(); // For any error msgs

			/*****************************
			 * List this system's devices
			 *****************************/
			int r = Pcap.findAllDevs(alldevs, errbuf);
			if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
				System.err.printf("Can't read list of devices, error is %s",
						errbuf.toString());
				return;
			}
			PcapIf device = alldevs.get(0); // There's at least 1 device

			/***************************
			 * Opens network interface.
			 ***************************/
			int snaplen = 64 * 1024; // Capture all packets, no truncation
			int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
			int timeout = 10 * 1000; // 10 seconds in milliseconds
			pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout,
					errbuf);

			/**********************************************
			 * Creates the packet about to be transmitted.
			 **********************************************/
			JPacket packet = assemblePacket();

			/*******************
			 * Send the packet.
			 *******************/
			if (pcap.sendPacket(packet) != Pcap.OK) {
				System.err.println(pcap.getErr());
			} else {
				System.out.println("SYN packet was sent.");
				
			}

			/*************************
			 * Listens for responses.
			 *************************/

			waitForIt();
		}
	}

	private static void printUsage() {

		System.out.println("Knocker application usage:");
		System.out
				.println("\tjava -jar Knocker.jar <remote_host_IP_address> <remote_host_port> <local_sending_port>");
		System.out
				.println("Please make sure to provide all arguments, in the correct order, for correct application functioning.");

	}

	private static void waitForIt() {
		PcapPacketHandler<String> packetHandler = new PcapPacketHandler<String>() {

			public void nextPacket(PcapPacket packet, String user) {

				Ip4 ip = new Ip4();
				Tcp tcp = new Tcp();

				if (packet != null) {

					if (packet.hasHeader(ip)) {

						if (packet.hasHeader(tcp)) {

							if (tcp.flags_ACK() && tcp.ack() == SEQ + 1) {
								System.out.println("received ack!");
								byte[] source = ip.source();
								System.out.println("ACK received from "
										+ FormatUtils.ip(source));
								System.out.println("ACK number: " + tcp.ack());
							}
							
						}

					}
				}
			}
		};

		System.out.print("Waiting for ACK... ");
		pcap.loop(1000, packetHandler, "Capturing data.");

		pcap.close();

	}

	private static JPacket assemblePacket() {
		JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, packetBytesString);

		Ip4 ip = packet.getHeader(new Ip4());
		Tcp tcp = packet.getHeader(new Tcp());

		tcp.destination(remotePort);// 80);
		tcp.seq(SEQ);

		ip.checksum(ip.calculateChecksum());
		tcp.checksum(tcp.calculateChecksum());
		packet.scan(Ethernet.ID);

		tcp.ack(0);
		tcp.flags_SYN(true);
		tcp.flags_ACK(false);
		tcp.flags_PSH(false);
		ip.destination(remoteAddress);// new byte[] { (byte) 200, (byte) 196,
		// (byte) 165, 18 });

		try {
			localAddress = Inet4Address.getLocalHost().getAddress();
			ip.source(localAddress);
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		ip.checksum(ip.calculateChecksum());
		tcp.checksum(tcp.calculateChecksum());
		packet.scan(Ethernet.ID);

		System.out.println("The produced packet is:");
		System.out.println(packet);
		System.out.println("=======================");

		return packet;
	}

}
