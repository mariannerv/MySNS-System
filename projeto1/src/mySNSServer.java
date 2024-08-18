import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.Mac;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

public class mySNSServer extends Thread {

    private void startServer(int port) {
        
        ServerSocket serverSocket = null;
        try {
            // serverSocket = new ServerSocket(port);
            System.setProperty("javax.net.ssl.keyStore", "ficheiros/servidor/server.keystore");
            System.setProperty("javax.net.ssl.keyStorePassword", "123456");

            ServerSocketFactory serverbServerSocketFactory = SSLServerSocketFactory.getDefault();
            serverSocket = serverbServerSocketFactory.createServerSocket(port);

            System.out.println("Server connected");

            // verificar se a pasta do admin existe ou não
            File utenteFolder = new File("ficheiros/servidor/admin/");
            if (!utenteFolder.exists()) {
                System.out.println("Admin folder does not exist yet");
                if (utenteFolder.mkdirs()) {
                    System.out.println("Folder for admin created: " + utenteFolder.getAbsolutePath());
                } else {
                    System.err.println("Failed to create folder for admin.");
                    return;
                }
            }

            
            File ficheiroUsers = new File("ficheiros/servidor/admin/users.txt");
            if (!ficheiroUsers.exists()) {
                System.out.println("A criar ficheiro users.txt ....");

                FileOutputStream fos = new FileOutputStream("ficheiros/servidor/admin/users.txt");

                // Get password from user input
                Scanner reader = new Scanner(System.in);
                System.out.println("Escreva a password do admin: ");
                String password = reader.nextLine();
                reader.close();

                byte[] salt = saltPassword();

                String saltLegivel = Base64.getEncoder().encodeToString(salt);
                String hashDaPassSalteada = getHashPassSalt(password, salt);

                String resultado = "admin;" + saltLegivel + ";" + hashDaPassSalteada;

                FileWriter writer = new FileWriter("ficheiros/servidor/admin/users.txt", true);
                BufferedWriter b = new BufferedWriter(writer);

                b.append(resultado + "\n");
                b.close();
                System.out.println("Password salted and encrypted: " + resultado);
                
                
			    System.out.println("A criar ficheiro users.txt.mac ....");
		        try (BufferedReader readerAdmin = new BufferedReader(new FileReader("ficheiros/servidor/admin/users.txt"))) {
		        	String firstLine = readerAdmin.readLine();
		        	
		        	String[] partsAdmin = firstLine.split(";");
		        	
		        	if (partsAdmin.length == 3 && partsAdmin[0].equals("admin")) {
		        		String saltAdmin = partsAdmin[1];
		        		String hashedPasswordAdmin = partsAdmin[2];
		        		//fazer hash da password do input com o salt guardado e comparar com a hash guardada.
		        		String decodedAdminPassword = decodeAdminPassword(hashedPasswordAdmin, Base64.getDecoder().decode(saltAdmin));
		        		checkAndUpdateUsersMac(decodedAdminPassword);
		        	}
		        }
                
                
            } else {
                Scanner reader = new Scanner(System.in);
                System.out.println("Insira a password do Admin: ");
                String password = reader.nextLine();
                byte[] passwordBytes = password.getBytes();
                reader.close();
                
                String ficheiroDePasses = "ficheiros/servidor/admin/users.txt";
                
                try (BufferedReader reader2 = new BufferedReader(new FileReader(ficheiroDePasses))) {
                    String line;
                    while ((line = reader2.readLine()) != null) {
                        String[] parts = line.split(";");
                        if (parts.length == 3 && parts[0].equals("admin")) {
                            
                            String salt = parts[1];
                            String hashedPassword = parts[2];
                            
                            //fazer hash da password do input com o salt guardado e comparar com a hash guardada.
                            String hashedInputPassword = getHashPassSalt(password, Base64.getDecoder().decode(salt));

                            if (hashedInputPassword.equals(hashedPassword)) {
                                System.out.println("Password correta, bem vindo de volta");
                            } else {
                                System.out.println("Password errada, servidor encerrado.");
                                System.exit(-1);
                            }

                            break; 
                           
                           
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
			    System.out.println("A verificar ficheiro users.txt.mac ....");
		        try (BufferedReader readerAdmin = new BufferedReader(new FileReader(ficheiroDePasses))) {
		        	String firstLine = readerAdmin.readLine();
		        	
		        	String[] partsAdmin = firstLine.split(";");
		        	
		        	if (partsAdmin.length == 3 && partsAdmin[0].equals("admin")) {
		        		String saltAdmin = partsAdmin[1];
		        		String hashedPasswordAdmin = partsAdmin[2];
		        		//fazer hash da password do input com o salt guardado e comparar com a hash guardada.
		        		String decodedAdminPassword = decodeAdminPassword(hashedPasswordAdmin, Base64.getDecoder().decode(saltAdmin));
		        		checkAndUpdateUsersMac(decodedAdminPassword);
		        	}
		        }
            
            }

            while (true) {
                Socket clientSocket = serverSocket.accept();
                ServerThread newServerThread = new ServerThread(clientSocket);
                newServerThread.start();
            }

        } catch (IOException e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        } finally {
            try {
                if (serverSocket != null) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                System.err.println("Error closing server socket: " + e.getMessage());
            }
        }
    }
    
    private void checkAndUpdateUsersMac(String password) {
        try {
            File usersFile = new File("ficheiros/servidor/admin/users.txt");
            File macFile = new File("ficheiros/servidor/admin/users.txt.mac");

            if (!macFile.exists() || usersFile.lastModified() > macFile.lastModified()) {
            	if(!macFile.exists()) {
            		// Se o arquivo users.txt.mac não existe ou se o users.txt foi modificado após o users.txt.mac, atualize o arquivo mac
	                createUsersMac(password);
	                byte[] calculatedMac = calculateMac(usersFile, password);
	                byte[] storedMac = readStoredMac(macFile);
	                if (!Arrays.equals(calculatedMac, storedMac)) {
	                    System.err.println("Error: User data integrity compromised. Shutting down server.");
	                    System.exit(-1);
	                } else {
	                    System.out.println("User data integrity verified.");
	                }
            	}
            	if(usersFile.lastModified() > macFile.lastModified()) {
            		// Se o arquivo users.txt.mac não existe ou se o users.txt foi modificado após o users.txt.mac, atualize o arquivo mac
	                updateUsersMac(password);
	                byte[] calculatedMac = calculateMac(usersFile, password);
	                byte[] storedMac = readStoredMac(macFile);
	                if (!Arrays.equals(calculatedMac, storedMac)) {
	                    System.err.println("Error: User data integrity compromised. Shutting down server.");
	                    System.exit(-1);
	                } else {
	                    System.out.println("User data integrity verified.");
	                }
            	}
                
            } else {
                // Se o arquivo users.txt.mac existe e users.txt não foi modificado, verifica a consistência
                byte[] calculatedMac = calculateMac(usersFile, password);
                byte[] storedMac = readStoredMac(macFile);
                if (!Arrays.equals(calculatedMac, storedMac)) {
                    System.err.println("Error: User data integrity compromised. Shutting down server.");
                    System.exit(-1);
                } else {
                    System.out.println("User data integrity verified.");
                }
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            System.err.println("Error checking and updating users.txt.mac: " + e.getMessage());
        }
    }

    private void updateUsersMac(String password) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        File usersFile = new File("ficheiros/servidor/admin/users.txt");
        byte[] mac = calculateMac(usersFile, password);
        File macFile = new File("ficheiros/servidor/admin/users.txt.mac");
        try (FileOutputStream fos = new FileOutputStream(macFile)) {
            fos.write(mac);
            System.out.println("MAC synthesis file updated successfully.");
        }
    }
    
    private void createUsersMac(String password) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        File usersFile = new File("ficheiros/servidor/admin/users.txt");
        byte[] mac = calculateMac(usersFile, password);
        File macFile = new File("ficheiros/servidor/admin/users.txt.mac");
        try (FileOutputStream fos = new FileOutputStream(macFile)) {
            fos.write(mac);
            System.out.println("MAC synthesis file created successfully.");
        }
    }


    private byte[] calculateMac(File file, String password) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        SecretKeySpec keySpec = new SecretKeySpec(password.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                mac.update(buffer, 0, bytesRead);
            }
        }
        return mac.doFinal();
    }

    private byte[] readStoredMac(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
            return bos.toByteArray();
        }
    }

    public static byte[] saltPassword() {

        // gerar chave salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        return salt;
    }

    public static String getHashPassSalt(String password, byte[] salt) {
        try {
            // password, salt, iteration count, key length
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hashedPassword);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("An error occurred: " + e.getMessage());
            return null; 
        }
    }
    
    public static String decodeAdminPassword(String password, byte[] salt) {
		try {
            byte[] encryptedPasswordBytes = Base64.getDecoder().decode(password);
            String adminPass = new String(encryptedPasswordBytes);
            PBEKeySpec spec = new PBEKeySpec(adminPass.toCharArray(), salt, 65536, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
            
            String decryptedPassword = new String(hashedPassword);

            return decryptedPassword;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
	}

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("You must provide a port.");
            System.exit(-1);
        }

        if (!VerifyAddress.isValidPort(args[0])) {
            System.err.println("Provided port must be valid.");
            System.exit(-1);
        }

        int port = Integer.parseInt(args[0]);

        mySNSServer server = new mySNSServer();
        server.startServer(port);
    }

}