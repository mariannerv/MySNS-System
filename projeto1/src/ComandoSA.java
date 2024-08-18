import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

/*
 *  Assina um ou mais ficheiros e envia-os para o servidor
 */
public class ComandoSA {

    private String ip;
    private int port;
    private String medico;
    private String utente;
    private List<String> files;
    private KeyStore keyStore;
    private String password;
    
    private static final String CLIENT_FOLDER = "ficheiros/cliente/";
    private static final String KEYSTORE_PASSWORD = "123456";

    public ComandoSA(String ip, int port, String medico, String utente, String password, List<String> files) {
        this.ip = ip;
        this.port = port;
        this.medico = medico;
        this.utente = utente;
        this.files = files;
        this.password = password;
        initializeKeyStore();
    }

    public void execute() {
        try {
            System.setProperty("javax.net.ssl.trustStore", CLIENT_FOLDER + "client.truststore");
            System.setProperty("javax.net.ssl.trustStorePassword", "123456");

            SocketFactory socketFactory = SSLSocketFactory.getDefault();
            Socket socket = socketFactory.createSocket(ip, port);

            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());

            objectOutputStream.writeObject("-sa");
            objectOutputStream.writeObject(medico);
            objectOutputStream.writeObject(utente);
            objectOutputStream.writeObject(password);

            // Read authentication result from the server
            boolean isAuthenticated = (Boolean) objectInputStream.readObject();
            if (!isAuthenticated) {
                System.err.println("Authentication failed: Password incorreta.");
                socket.close();
                return; // Exit method if authentication fails
            }

            objectOutputStream.writeInt(files.size());

            for (String fileName : files) {

                File file = new File(CLIENT_FOLDER + fileName);
                if (!file.exists()) {
                    System.err.println("File " + fileName + " does not exist");
                    continue;
                }

                if (isFileOnRemote(fileName, objectInputStream, objectOutputStream)) {
                    System.err.println("File " + fileName + " is already on remote");
                    continue;
                }

                PrivateKey privateKey = getClientKey();
                if (privateKey == null) {
                    System.err.println("Failed to retrieve private key. Cannot sign the file.");
                    continue;
                }

                byte[] signatureData = signFile(file, privateKey);
                if (signatureData == null) {
                    System.err.println("Failed to sign the file " + fileName);
                    continue;
                }

                sendToServer(file, signatureData, objectOutputStream);
            }

            objectOutputStream.close();
            objectInputStream.close();
            socket.close();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("An error occurred");
            e.printStackTrace();
        }
    }


    private boolean isFileOnRemote(String fileName, ObjectInputStream objectInputStream,
            ObjectOutputStream objectOutputStream) {
        try {
            objectOutputStream.writeObject(fileName);
            boolean isFileOnRemote = (boolean) objectInputStream.readObject();
            return isFileOnRemote;
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("An I/O error occurred");
            e.printStackTrace();
        }
        throw new Error("Error verifying if file " + fileName + " is already on remote");
    }

    private void initializeKeyStore() {
        File file = new File(CLIENT_FOLDER, String.format("%s.keystore", medico));
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            this.keyStore = KeyStore.getInstance("PKCS12");
            this.keyStore.load(fileInputStream, KEYSTORE_PASSWORD.toCharArray());
        } catch (FileNotFoundException e) {
            System.err.println("Keystore file does not exist for medico: " + medico);
            e.printStackTrace();
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            System.err.println("Error occurred while loading the keystore");
            e.printStackTrace();
        }
    }

    public PrivateKey getClientKey() {
        try {
            return (PrivateKey) this.keyStore.getKey(medico, KEYSTORE_PASSWORD.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            System.err.println("Could not retrieve the key for medico: " + medico);
            e.printStackTrace();
            return null;
        }
    }

    public byte[] signFile(File file, PrivateKey privateKey) {
        try {
            // Open streams
            FileInputStream fileInputStream = new FileInputStream(file);
            BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);

            // Sign File
            System.out.println("Signing " + file.getName() + " with SHA256withRSA...");
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = bufferedInputStream.read(buffer)) != -1) {
                signature.update(buffer, 0, bytesRead);
            }
            byte[] signatureData = signature.sign();

            System.out.println(file.getName() + " signed!");

            // Close the file input stream
            bufferedInputStream.close();
            fileInputStream.close();

            return signatureData;

        } catch (FileNotFoundException e) {
            System.err.println("File not found: " + file.getName());
            e.printStackTrace();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
            System.err.println("An error occurred while signing the file: " + file.getName());
            e.printStackTrace();
        }

        return null;
    }

    private void sendToServer(File file, byte[] signatureData, ObjectOutputStream objectOutputStream) {
        try {

            String fileName = file.getName() + ".assinado";
            long fileSize = file.length();
            
            
            
            // Send file name and size
            objectOutputStream.writeObject(fileName);
            objectOutputStream.writeLong(fileSize);
            
            
            
            
            // Send file content
            try (FileInputStream fileInputStream = new FileInputStream(file)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                    objectOutputStream.write(buffer, 0, bytesRead);
                }
            }
            objectOutputStream.flush();

            String signatureFileName = file.getName() + ".assinatura." + medico;

            // Send signature to the server
            objectOutputStream.writeObject(signatureFileName);
            objectOutputStream.writeInt(signatureData.length);
            objectOutputStream.write(signatureData);
            objectOutputStream.flush();

            System.out.println("File and signature for " + file.getName() + " sent to server.");
        } catch (IOException e) {
            System.err.println("An I/O error occurred");
            e.printStackTrace();
        }
    }

}
