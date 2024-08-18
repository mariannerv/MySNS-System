import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.List;
import javax.crypto.*;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import java.security.cert.Certificate;

public class ComandoSE {

    private String ip;
    private int port;
    private String medico;
    private String utente;
    private List<String> files;
    private String password;

    public ComandoSE(String ip, int port, String medico, String utente, String password, List<String> files) {
        this.ip = ip;
        this.port = port;
        this.medico = medico;
        this.utente = utente;
        this.files = files;
        this.password = password;
    }

    public void sendToServer() {
        try {

            System.setProperty("javax.net.ssl.trustStore", "ficheiros/cliente/client.truststore");
            System.setProperty("javax.net.ssl.trustStorePassword", "123456");

            SocketFactory socketFactory = SSLSocketFactory.getDefault();
            Socket socket = socketFactory.createSocket(ip, port);

            ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());

            outStream.writeObject("-se");
            outStream.writeObject(files.size());
            
            outStream.writeObject(medico);
            outStream.writeObject(utente);
            outStream.writeObject(password);
            
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
                        cifrarFicheiro(fileName);
                        File fileCif = new File("ficheiros/servidor/" + fileName + ".seguro");
                        Long dimFileCif = fileCif.length();
                        outStream.writeObject(fileName + ".seguro");
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
                        assinarArquivo(fileName);
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void cifrarFicheiro(String ficheiro) {
        try {
            // Key generation for AES
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey key = kg.generateKey();

            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.ENCRYPT_MODE, key);

            // Encrypt file with AES
            FileInputStream fis = new FileInputStream("ficheiros/" + ficheiro);
            FileOutputStream fos = new FileOutputStream("ficheiros/servidor/" + ficheiro + ".seguro");
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

            String nomeCifrado = "ficheiros/servidor/" + ficheiro + ".seguro";
            File cipheredFile = new File(nomeCifrado);
            if (cipheredFile.exists()) {
                System.out.println("Ficheiro Cifrado criado com sucesso: " + cipheredFile.getAbsolutePath());
            } else {
                System.err.println("Falha na criação do Ficheiro Cifrado.");
            }
            
            String chaveSecreta = "ficheiros/servidor/" + ficheiro + ".chave_secreta." + utente;
            File secretKeyFile = new File(chaveSecreta);
            if (secretKeyFile.exists()) {
                System.out.println("Ficheiro Chave Secreta criado com successo: " + secretKeyFile.getAbsolutePath());
            } else {
                System.err.println("Falha na criação do Ficheiro Chave Secreta.");
            }
            if (cipheredFile.exists() && secretKeyFile.exists()) {
                System.out.println("Ficheiro Cifrado e Chave Secreta criados com sucesso.");
            } else {
                System.err.println("Falha na criação do Ficheiro Cifrado e Chave Secreta.");
            }
            
            medicoKeystoreFile.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void assinarArquivo(String ficheiro) {
        try {
            FileInputStream medicoKeystoreFile = new FileInputStream("ficheiros/cliente/" + medico + ".keystore");
            KeyStore medicoKeystore = KeyStore.getInstance("PKCS12");
            medicoKeystore.load(medicoKeystoreFile, "123456".toCharArray());
            PrivateKey privateKey = (PrivateKey) medicoKeystore.getKey(medico, "123456".toCharArray());

            // Inicializar assinatura
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);

            // Ler o conteúdo do arquivo para assinar
            FileInputStream fileInputStream = new FileInputStream("ficheiros/" + ficheiro);
            FileOutputStream ficheiroBase = new FileOutputStream(
                    "ficheiros/servidor/" + utente + "/" + ficheiro + ".assinado");
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                signature.update(buffer, 0, bytesRead);
                ficheiroBase.write(buffer, 0, bytesRead);
            }
            fileInputStream.close();
            ficheiroBase.close();

            // Assinar o conteúdo do arquivo
            byte[] assinatura = signature.sign();

            // Salvar a assinatura em um arquivo com o mesmo nome do arquivo original
            String nomeAssinatura = "ficheiros/servidor/" + utente + "/" + ficheiro + ".assinatura." + medico;
            FileOutputStream fileOutputStream = new FileOutputStream(nomeAssinatura);
            fileOutputStream.write(assinatura);
            fileOutputStream.close();

            // Verificar se o arquivo foi criado
            File signedFile = new File(nomeAssinatura);
            if (signedFile.exists()) {
                System.out.println("Signed file created successfully: " + signedFile.getAbsolutePath());
            } else {
                System.err.println("Signed file creation failed.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
