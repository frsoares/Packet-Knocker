package br.poli.ecomp.knocker;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

	public static void main(String[] args) {
		try {
			/*ServerSocket s = new ServerSocket(65521);
			
			Socket sock = s.accept();
			
			System.out.println(sock.getLocalAddress().getHostAddress() + " - " + sock.getRemoteSocketAddress() );
			*/
			
			Socket s = new Socket("200.196.165.18", 80);
			
			s.close();
			
			
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
}
