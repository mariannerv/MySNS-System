import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.Mac;

public class ServerThread extends Thread {

	// Server socket
	public Socket socket = null;

	// Thread server for each client
	public ServerThread(Socket inSoc) {
		this.socket = inSoc;
	}

	private static final String BASE_DIR = "ficheiros/servidor/";

	public void run() {
		try {
			ObjectInputStream inStream = new ObjectInputStream(this.socket.getInputStream());
			ObjectOutputStream outStream = new ObjectOutputStream(this.socket.getOutputStream());

			String option = (String) inStream.readObject();
			System.out.println("Opcao: " + option);

			if (option.equals("-sc")) {
				verifyCommandSC(inStream, outStream);
			} else if (option.equals("-se")) {
				handleCommandSE(inStream, outStream);
			} else if (option.equals("-sa")) {
				handleCommandSA(inStream, outStream);
			} else if (option.equals("-g")) {
				verifyCommandG(inStream, outStream);
			} else if (option.equals("-au")) {
				verifyCommandAU(inStream, outStream);
			}

			inStream.close();
			this.socket.close();

		} catch (IOException | ClassNotFoundException e) {
			System.out.println("I got an error or something was interrupted!");
			e.printStackTrace();
		}
	}

	private void handleCommandSA(ObjectInputStream inStream, ObjectOutputStream outStream) {
	    try {
	        File ficheiroUsers = new File("ficheiros/servidor/admin/users.txt");
	        String medico = (String) inStream.readObject();
	        String alias = (String) inStream.readObject();
	        String password = (String) inStream.readObject();
	        
	        boolean isAuthenticated = false; // Authentication flag
	        
	        try (BufferedReader reader2 = new BufferedReader(new FileReader(ficheiroUsers))) {
	            String line;
	            while ((line = reader2.readLine()) != null) {
	                String[] parts = line.split(";");
	                if (parts.length == 3 && parts[0].equals(medico)) {
	                    
	                    String salt = parts[1];
	                    String hashedPassword = parts[2];
	                    
	                    //fazer hash da password do input com o salt guardado e comparar com a hash guardada.
	                    String hashedInputPassword = getHashPassSalt(password, Base64.getDecoder().decode(salt));

	                    if (hashedInputPassword.equals(hashedPassword)) {
	                        System.out.println("Password correta");
	                        isAuthenticated = true; // Set flag to true if password matches
	                    } else {
	                        System.out.println("Password errada");
	                    }

	                    break; 
	                }
	            }
	        } catch (IOException e) {
	            e.printStackTrace();
	        }
	        
	        // Send authentication result to the client
	        outStream.writeObject(isAuthenticated);
	        
	        if (!isAuthenticated) {
	            return; // Exit method if authentication fails
	        }

	        // Ensure client folder exists
	        File clientFolder = new File("ficheiros/servidor/" + alias);
	        if (!clientFolder.exists()) {
	            clientFolder.mkdirs();
	        }

	        // Read number of files
	        int numFiles = inStream.readInt();
	        for (int i = 0; i < numFiles; i++) {

	            // is file on remote ?
	            String rawFileName = (String) inStream.readObject();
	            File[] matchingFiles = clientFolder.listFiles(new FilenameFilter() {
	                public boolean accept(File dir, String name) {
	                    return name.startsWith(rawFileName);
	                }
	            });

	            if (matchingFiles != null && matchingFiles.length > 0) {
	                outStream.writeObject(true);
	                continue;
	            }
	            outStream.writeObject(false);

	            // Store the file
	            // Read file name and size
	            String fileName = (String) inStream.readObject();
	            long fileSize = inStream.readLong();

	            // Save the file
	            saveFile(inStream, clientFolder.getPath() + "/" + fileName, fileSize);

	            // Read signature file name and size
	            String signatureFileName = (String) inStream.readObject();
	            int signatureFileSize = inStream.readInt();

	            // Save the signature file
	            saveFile(inStream, clientFolder.getPath() + "/" + signatureFileName, signatureFileSize);

	            System.out.println("Received file and signature successfully.");
	        }

	    } catch (ClassNotFoundException | IOException e) {
	        System.err.println("Error occurred during -sa command handling.");
	    }
	}


	private void saveFile(ObjectInputStream inStream, String outputPath, long fileSize) {
		try {
			byte[] buffer = new byte[1024];
			long bytesRead = 0;

			try (FileOutputStream fileOutputStream = new FileOutputStream(outputPath)) {
				while (bytesRead < fileSize) {
					int read = inStream.read(buffer, 0, buffer.length);
					fileOutputStream.write(buffer, 0, read);
					bytesRead += read;
				}
			}
		} catch (IOException e) {
			System.err.println("Error saving file to: " + outputPath);
			e.printStackTrace();
		}
	}

	private void verifyCommandSC(ObjectInputStream inStream, ObjectOutputStream outStream) {
	    try {
	        File ficheiroUsers = new File("ficheiros/servidor/admin/users.txt");
	        int filesDim = (int) inStream.readObject();
	        
	        String medico = (String) inStream.readObject();
	        String utente = (String) inStream.readObject();
	        System.out.println("Utente received: " + utente);
	        String password = (String) inStream.readObject();
	        System.out.println("Password recebida");
	        
	        boolean isAuthenticated = false; // Add this flag
	        
	        try (BufferedReader reader2 = new BufferedReader(new FileReader(ficheiroUsers))) {
	            String line;
	            while ((line = reader2.readLine()) != null) {
	                String[] parts = line.split(";");
	                if (parts.length == 3 && parts[0].equals(medico)) {
	                    
	                    String salt = parts[1];
	                    String hashedPassword = parts[2];
	                    
	                    //fazer hash da password do input com o salt guardado e comparar com a hash guardada.
	                    String hashedInputPassword = getHashPassSalt(password, Base64.getDecoder().decode(salt));

	                    if (hashedInputPassword.equals(hashedPassword)) {
	                        System.out.println("Password correta");
	                        isAuthenticated = true; // Set flag to true if password matches
	                    } else {
	                        System.out.println("Password errada");
	                    }

	                    break; 
	                }
	            }
	        } catch (IOException e) {
	            e.printStackTrace();
	        }

	        // Send authentication result to the client
	        outStream.writeObject(isAuthenticated);

	        if (!isAuthenticated) {
	            return; // Exit method if authentication fails
	        }

	        File utenteFolder = new File(BASE_DIR + utente + "/");
	        if (!utenteFolder.exists()) {
	            if (utenteFolder.mkdirs()) {
	                System.out.println("Folder for utente created: " + utenteFolder.getAbsolutePath());
	            } else {
	                System.err.println("Failed to create folder for utente.");
	                return; // Exit method if folder creation fails
	            }
	        }

	        for (int i = 0; i < filesDim; i++) {
	            Boolean fileExistClient = (Boolean) inStream.readObject();

	            if (fileExistClient) {
	                String fileName = (String) inStream.readObject();

	                // Construct absolute paths using BASE_DIR
	                File fcifrado = new File(utenteFolder, fileName + ".cifrado");

	                Boolean fileExistServer = fcifrado.exists();
	                outStream.writeObject(fileExistServer);

	                if (!fileExistServer) {
	                    // Receive the cipher file
	                    String fileNameCif = (String) inStream.readObject();
	                    FileOutputStream outFileStreamCif = new FileOutputStream(fcifrado);
	                    BufferedOutputStream outFileCif = new BufferedOutputStream(outFileStreamCif);

	                    try {
	                        receiveFile(inStream, outFileCif);
	                        outFileCif.close();
	                    } catch (IOException e) {
	                        e.printStackTrace();
	                    }

	                    // Receive the cipher key
	                    String fileNameKey = (String) inStream.readObject();
	                    FileOutputStream outFileStreamKey = new FileOutputStream(new File(utenteFolder, fileNameKey));
	                    BufferedOutputStream outFileKey = new BufferedOutputStream(outFileStreamKey);

	                    try {
	                        receiveFile(inStream, outFileKey);
	                        outFileKey.close();
	                    } catch (IOException e) {
	                        e.printStackTrace();
	                    }

	                    System.out.println("The file " + fileName + " received!");
	                } else {
	                    System.out.println("The file " + fileName + " already exists on the server.");
	                }
	            }
	        }
	    } catch (IOException | ClassNotFoundException e) {
	        System.err.println("Ocorreu um erro do lado do cliente");
	    }
	}


	private void handleCommandSE(ObjectInputStream inStream, ObjectOutputStream outStream) {
		try {
			int filesDim = (int) inStream.readObject();
			File ficheiroUsers = new File("ficheiros/servidor/admin/users.txt");
			String medico = (String) inStream.readObject();
			String utente = (String) inStream.readObject();
			System.out.println("Utente recebido: " + utente);
			String password = (String) inStream.readObject();
			System.out.println("Password recebida");
			boolean isAuthenticated = false; // Add this flag
	        
	        try (BufferedReader reader2 = new BufferedReader(new FileReader(ficheiroUsers))) {
	            String line;
	            while ((line = reader2.readLine()) != null) {
	                String[] parts = line.split(";");
	                if (parts.length == 3 && parts[0].equals(medico)) {
	                    
	                    String salt = parts[1];
	                    String hashedPassword = parts[2];
	                    
	                    //fazer hash da password do input com o salt guardado e comparar com a hash guardada.
	                    String hashedInputPassword = getHashPassSalt(password, Base64.getDecoder().decode(salt));

	                    if (hashedInputPassword.equals(hashedPassword)) {
	                        System.out.println("Password correta");
	                        isAuthenticated = true; // Set flag to true if password matches
	                    } else {
	                        System.out.println("Password errada");
	                    }

	                    break; 
	                }
	            }
	        } catch (IOException e) {
	            e.printStackTrace();
	        }

	        // Send authentication result to the client
	        outStream.writeObject(isAuthenticated);

	        if (!isAuthenticated) {
	            return; // Exit method if authentication fails
	        }
			File utenteFolder = new File(BASE_DIR + utente + "/");
			if (!utenteFolder.exists()) {
				if (utenteFolder.mkdirs()) {
					System.out.println("Folder for utente created: " + utenteFolder.getAbsolutePath());
				} else {
					System.err.println("Failed to create folder for utente.");
					return; // Exit method if folder creation fails
				}
			}

			for (int i = 0; i < filesDim; i++) {
				Boolean fileExistClient = (Boolean) inStream.readObject();

				if (fileExistClient) {
					String fileName = (String) inStream.readObject();

					// Construct absolute paths using BASE_DIR
					File fcifrado = new File(utenteFolder, fileName + ".seguro");

					Boolean fileExistServer = fcifrado.exists();
					outStream.writeObject(fileExistServer);

					if (!fileExistServer) {
						// Receive the cipher file
						String fileNameCif = (String) inStream.readObject();
						FileOutputStream outFileStreamCif = new FileOutputStream(fcifrado);
						BufferedOutputStream outFileCif = new BufferedOutputStream(outFileStreamCif);

						try {
							receiveFile(inStream, outFileCif);
							outFileCif.close();
						} catch (IOException e) {
							e.printStackTrace();
						}

						// Receive the cipher key
						String fileNameKey = (String) inStream.readObject();
						FileOutputStream outFileStreamKey = new FileOutputStream(new File(utenteFolder, fileNameKey));
						BufferedOutputStream outFileKey = new BufferedOutputStream(outFileStreamKey);

						try {
							receiveFile(inStream, outFileKey);
							outFileKey.close();
						} catch (IOException e) {
							e.printStackTrace();
						}

						System.out.println("The file " + fileName + " received!");
					} else {
						System.out.println("The file " + fileName + " already exists on the server.");
					}
				}
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

	private void verifyCommandG(ObjectInputStream inStream, ObjectOutputStream outStream) {
		try {
			String alias = (String) inStream.readObject();
			File clientFolder = new File("ficheiros/servidor/" + alias);

			// se client folder não existe, os ficheiros não estão no servidor
			if (!clientFolder.exists()) {
				outStream.writeObject(false);
				System.err.println("Pasta do utente " + alias + " nao existe no servidor");
				return;
			}
			outStream.writeObject(true);

			int numFiles = inStream.readInt();
			for (int i = 0; i < numFiles; i++) {

				String fileName = (String) inStream.readObject();

				boolean cipheredExists = false;
				boolean signedExists = false;
				boolean securedCipheredExists = false;

				File cipheredFile = null;
				File signedFile = null;
				File securedCipheredFile = null;
				if (clientFolder.exists()) {
					securedCipheredFile = new File(clientFolder.getPath() + "/" + fileName + ".seguro");
					cipheredFile = new File(clientFolder.getPath() + "/" + fileName + ".cifrado");
					signedFile = new File(clientFolder.getPath() + "/" + fileName + ".assinado");

					securedCipheredExists = securedCipheredFile.exists();
					cipheredExists = cipheredFile.exists();
					signedExists = signedFile.exists();
				}
				outStream.writeObject(securedCipheredExists);
				outStream.writeObject(cipheredExists);
				outStream.writeObject(signedExists);

				if (securedCipheredExists && signedExists) {
					System.out.println(" .cifrado and .assinado and .seguro files exist.");

					// Send signed file
					sendFile(signedFile, outStream);

					// Send signature file
					File signatureFile = findSignatureFile(clientFolder, fileName);
					if (signatureFile != null) {
						sendFile(signatureFile, outStream);
					} else {
						System.err.println("Signature file not found for file: " + fileName);
					}

				} else if (cipheredExists) {
					System.out.println("Only .cifrado file exist.");

					// Enviar ficheiros para decifrar
					try (FileInputStream fileInStreamSecretKey = new FileInputStream(
							clientFolder.getPath() + "/" + fileName + ".chave_secreta." + alias)) {
						outStream.write(fileInStreamSecretKey.readAllBytes());
					}

				} else if (signedExists) {
					// Send signed file
					sendFile(signedFile, outStream);

					// Send signature file
					File signatureFile = findSignatureFile(clientFolder, fileName);
					if (signatureFile != null) {
						sendFile(signatureFile, outStream);
					} else {
						System.err.println("Signature file not found for file: " + fileName);
					}

				} else {
					System.err.println("File " + fileName + " does not exits remotely");
				}
			}

		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	private void verifyCommandAU(ObjectInputStream inStream, ObjectOutputStream outStream) throws ClassNotFoundException, IOException {
	    String ficheiroDePasses = "ficheiros/servidor/admin/users.txt";
	    String username = (String) inStream.readObject();
	    System.out.println("Utilizador recebido, processo iniciado:");

	    // Verificar se já existe
	    try (BufferedReader reader2 = new BufferedReader(new FileReader(ficheiroDePasses))) {
	        String line;
	        boolean userExists = false; // Flag to track if the username already exists
	        while ((line = reader2.readLine()) != null) {
	            String[] parts = line.split(";");
	            if (parts.length == 3 && parts[0].equals(username)) {
	                // Username already exists
	                userExists = true;
	                System.out.println("Utilizador já existe: " + username);
	                outStream.writeObject("nok");
	                break; // Exit the loop if a match is found
	            }
	        }
	        if (!userExists) {
	            // Username is available, proceed with registration
	            outStream.writeObject("Utilizador disponivel");
	            String password;
	            try {
	                password = (String) inStream.readObject();
	            } catch (ClassNotFoundException e) {
	                // Handle the exception
	                e.printStackTrace();
	                return;
	            }

	            byte[] salt = saltPassword();
	            String saltLegivel = Base64.getEncoder().encodeToString(salt);
	            String hashDaPassSalteada = getHashPassSalt(password, salt);

	            try (FileWriter writer = new FileWriter("ficheiros/servidor/admin/users.txt", true);
	                 BufferedWriter b = new BufferedWriter(writer)) {

	                String resultado = username + ";" + saltLegivel + ";" + hashDaPassSalteada;
	                b.append(resultado + "\n");
	                
	                System.out.println("Novo utilizador registado com sucesso: " + resultado);

	                //Criar a diretoria caso não exista
	                File utenteFolder = new File(BASE_DIR + username);
	                if (!utenteFolder.exists()) {
	                    if (utenteFolder.mkdirs()) {
	                        System.out.println("Folder for utente created: " + utenteFolder.getAbsolutePath());
	                    } else {
	                        System.err.println("Failed to create folder for utente.");
	                        return;
	                    }
	                }
	                
	                Long certDimLong = (Long) inStream.readObject();
	                long certDim = certDimLong; // Long to long conversion
	                String cert = (String) inStream.readObject();
	                File fcifrado = new File("ficheiros/servidor/certificados/" + cert);
	                try (FileOutputStream outFileStreamCif = new FileOutputStream(fcifrado);
	                     BufferedOutputStream outFileCif = new BufferedOutputStream(outFileStreamCif)) {
	                    byte[] buffer = new byte[1024];
	                    int bytesRead;
	                    long bytesReadTotal = 0;
	                    while (bytesReadTotal < certDim) {
	                        int bytesToRead = (int) Math.min(certDim - bytesReadTotal, buffer.length);
	                        bytesRead = inStream.read(buffer, 0, bytesToRead);
	                        if (bytesRead == -1) {
	                            // Unexpected end of stream
	                            throw new IOException("Unexpected end of stream while receiving file content.");
	                        }
	                        outFileCif.write(buffer, 0, bytesRead);
	                        bytesReadTotal += bytesRead;
	                    }
	                }
	                System.out.println("Certificado " + cert + " recebido!");
	                	}
	                }
	            }
	    
			  //parte minha
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
		        //acaba aqui
	        }
	
	
	private File findSignatureFile(File clientFolder, String fileNamePrefix) {
		FilenameFilter filter = (dir, name) -> name.startsWith(fileNamePrefix + ".assinatura.")
				&& name.length() > (fileNamePrefix + ".assinatura.").length();
		File[] files = clientFolder.listFiles(filter);

		return files != null && files.length > 0 ? files[0] : null;
	}

	private void sendFile(File file, ObjectOutputStream outStream) {
		String fileName = file.getName();
		long fileSize = file.length();
		try {
			outStream.writeObject(fileName);
			outStream.writeLong(fileSize);
			FileInputStream fileInputStream = new FileInputStream(file);
			byte[] buffer = new byte[1024];
			int bytesRead;
			while ((bytesRead = fileInputStream.read(buffer)) != -1) {
				outStream.write(buffer, 0, bytesRead);
			}
			outStream.flush();
			fileInputStream.close();
		} catch (IOException e) {
			System.out.println("Error sending file: " + file.getName());
			e.printStackTrace();
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
	
	
	
	private void receiveFile(ObjectInputStream inStream, BufferedOutputStream outFile) throws IOException {
		try {
			Long fileSize = (Long) inStream.readObject();
			int fileSizeInt = fileSize.intValue();
			byte[] bufferData = new byte[Math.min(fileSizeInt, 1024)];
			int contentLength = inStream.read(bufferData);

			while (fileSizeInt > 0 && contentLength > 0) {
				if (fileSizeInt >= contentLength) {
					outFile.write(bufferData, 0, contentLength);
				} else {
					outFile.write(bufferData, 0, fileSizeInt);
				}
				contentLength = inStream.read(bufferData);
				fileSizeInt -= contentLength;
			}
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} finally {
			outFile.close();
		}
	}
	
	
	
	
	
	
	
}
