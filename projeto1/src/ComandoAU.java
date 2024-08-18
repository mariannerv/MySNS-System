import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ConnectException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class ComandoAU {
	private String ip;
    private int port;
    private String user;
    private String password;
    private String certificado;
    
    public ComandoAU(String ip, int port, String user, String password, String certificado) {
    	this.ip = ip;
    	this.port = port;
    	this.user = user;
    	this.password = password;
    	this.certificado = certificado;
    }
    
    public void sendToServer() {
        try {
            System.setProperty("javax.net.ssl.trustStore", "ficheiros/cliente/client.truststore");
            System.setProperty("javax.net.ssl.trustStorePassword", "123456");

            SocketFactory socketFactory = SSLSocketFactory.getDefault();
            Socket socket = socketFactory.createSocket(ip, port);

            ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

            outStream.writeObject("-au");

            System.out.println("A enviar nome do utilizador...");
            outStream.writeObject(user);
            System.out.println("Nome enviado com sucesso!");

            Object response = inStream.readObject();
            String serverResponse = (String) response;
            if (serverResponse.equals("nok")) {
                System.out.println("O utilizador já existe. O processo foi terminado.");
                outStream.close();
                inStream.close();
                socket.close();
                return; 
            
            } else {
                System.out.println("A enviar password do utilizador...");
	            outStream.writeObject(password);
	            System.out.println("Password enviada com sucesso!");
	            
	            System.out.println("A enviar certificado ao servidor...");
	            File certFile = new File("ficheiros/cliente/" + certificado);
	            long fileSize = certFile.length();
	            outStream.writeObject(fileSize);
	            outStream.writeObject(certificado);
	            try (BufferedInputStream myCert = new BufferedInputStream(new FileInputStream(certFile))) {
	                byte[] buffer = new byte[1024];
	                int bytesRead;
	                while ((bytesRead = myCert.read(buffer)) != -1) {
	                    outStream.write(buffer, 0, bytesRead);
	                }
	            }
	            System.out.println("Certificado enviado!");
	            
	            outStream.close();
	            inStream.close();
	            socket.close();
           }
        } catch (ConnectException e) {
            System.err.println("Host ou porto não acessíveis.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }




    
    
    
    
}
