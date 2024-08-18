import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.List;
import javax.crypto.*;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class ComandoSC {

    private String ip;
    private int port;
    private String medico;
    private String utente;
    private List<String> files;
    private String password;

    public ComandoSC(String ip, int port, String medico, String utente, String password, List<String> files) {
        this.ip = ip;
        this.port = port;
        this.medico = medico;
        this.utente = utente;
        this.files = files;
        this.password = password;
    }
    
    
    
    

    private void cifraFicheiro(String ficheiro) {
        try {
            // Key generation for AES
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey key = kg.generateKey();

            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.ENCRYPT_MODE, key);

            // Encrypt file with AES
            FileInputStream fis = new FileInputStream("ficheiros/" + ficheiro);
            FileOutputStream fos = new FileOutputStream("ficheiros/servidor/" + ficheiro + ".cifrado");
            CipherOutputStream cos = new CipherOutputStream(fos, c);
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
            cos.close();
            fis.close();
            fos.close();

           
            FileInputStream medicoKeystoreFile = new FileInputStream("ficheiros/cliente/" + medico + ".keystore");
            KeyStore medicoKeystore = KeyStore.getInstance("PKCS12");
            medicoKeystore.load(medicoKeystoreFile, "123456".toCharArray());
            Certificate utenteCert = medicoKeystore.getCertificate(utente);
            if (utenteCert == null) {
                System.err.println("Erro: O certificado do utente '" + utente
                        + "' não se encontra na keystore do médico " + medico);
                System.exit(1); 
            }
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, utenteCert.getPublicKey());
            byte[] encryptedKey = rsaCipher.doFinal(key.getEncoded());

            // Save encrypted AES key
            FileOutputStream kos = new FileOutputStream("ficheiros/servidor/" + ficheiro + ".chave_secreta." + utente);
            kos.write(encryptedKey);
            kos.close();

            System.out.println("Ficheiro e chave encriptados com sucesso.");
            medicoKeystoreFile.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendToServer() {
        try {
            System.setProperty("javax.net.ssl.trustStore", "ficheiros/cliente/client.truststore");
            System.setProperty("javax.net.ssl.trustStorePassword", "123456");

            SocketFactory socketFactory = SSLSocketFactory.getDefault();
            Socket socket = socketFactory.createSocket(ip, port);

            ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

            outStream.writeObject("-sc");
            outStream.writeObject(files.size());
            
            outStream.writeObject(medico);
            outStream.writeObject(utente);
            outStream.writeObject(password);

            // Read authentication result from the server
            boolean isAuthenticated = (Boolean) inStream.readObject();
            if (!isAuthenticated) {
                System.err.println("Authentication failed: Password incorreta.");
                socket.close();
                return; 
            }

            for (String fileName : files) {
                File f = new File("ficheiros/" + fileName);
                Boolean fileExistClient = f.exists();
                outStream.writeObject(fileExistClient);
                if (fileExistClient) {
                    outStream.writeObject(fileName);
                    Boolean fileExistServer = (Boolean) inStream.readObject();
                    if (!fileExistServer) {
                        cifraFicheiro(fileName);
                        File fileCif = new File("ficheiros/servidor/" + fileName + ".cifrado");
                        Long dimFileCif = fileCif.length();
                        outStream.writeObject(fileName + ".cifrado");
                        outStream.writeObject(dimFileCif);
                        BufferedInputStream myFileCif = new BufferedInputStream(new FileInputStream(fileCif));
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        while ((bytesRead = myFileCif.read(buffer)) != -1) {
                            outStream.write(buffer, 0, bytesRead);
                        }
                        myFileCif.close();

                        File keyCif = new File("ficheiros/servidor/" + fileName + ".chave_secreta." + utente);
                        Long dimKeyCif = keyCif.length();
                        outStream.writeObject(fileName + ".chave_secreta." + utente);
                        outStream.writeObject(dimKeyCif);
                        BufferedInputStream myKeyCif = new BufferedInputStream(new FileInputStream(keyCif));
                        while ((bytesRead = myKeyCif.read(buffer)) != -1) {
                            outStream.write(buffer, 0, bytesRead);
                        }
                        myKeyCif.close();
                        keyCif.delete();
                        fileCif.delete();
                        System.out.println("O ficheiro " + fileName + " foi corretamente enviado.");
                    } else {
                        System.err.println("O ficheiro " + fileName + " já existe no servidor.");
                    }
                } else {
                    System.err.println("O ficheiro " + fileName + " Não existe. Escolha um ficheiro existente.");
                }
            }

            outStream.close();
            inStream.close();
            socket.close();
        } catch (ConnectException e) {
            System.err.println("Host ou porto não acessíveis.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
