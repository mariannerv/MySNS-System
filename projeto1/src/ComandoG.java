import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import javax.crypto.Cipher;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class ComandoG {

	private String ip;
	private int port;
	private String utente;
	private List<String> files;

	private static final String CLIENT_FOLDER = "ficheiros/cliente/";
	private static final String KEYSTORE_PASSWORD = "123456";

	public ComandoG(String ip, int port, String utente, List<String> files) {
		this.ip = ip;
		this.port = port;
		this.utente = utente;
		this.files = files;
	}

	public void sendToServer() {
		try {
			System.setProperty("javax.net.ssl.trustStore", CLIENT_FOLDER + "client.truststore");
			System.setProperty("javax.net.ssl.trustStorePassword", "123456");

			SocketFactory socketFactory = SSLSocketFactory.getDefault();
			Socket socket = socketFactory.createSocket(ip, port);

			ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
			ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());

			objectOutputStream.writeObject("-g");
			objectOutputStream.writeObject(utente);

			boolean clientFolderExists = (boolean) objectInputStream.readObject();
			if (!clientFolderExists) {
				System.err.println("Pasta do utente " + utente + " nao existe no servidor");
				return;
			}

			objectOutputStream.writeInt(files.size());

			for (String fileName : files) {

				File file = new File(CLIENT_FOLDER, fileName);
				if (file.exists()) {
					System.err.println("File " + fileName + " already exists locally");
					continue;
				}

				objectOutputStream.writeObject(fileName);

				boolean securedCipheredExists = (boolean) objectInputStream.readObject();
				boolean cipheredExists = (boolean) objectInputStream.readObject();
				boolean signedExists = (boolean) objectInputStream.readObject();

				if (securedCipheredExists && signedExists) {
					System.out.println("Both .cifrado and .assinado files exist.");

					// decifrar e verificar assinatura
					byte[] secretKeyInByte = new byte[256];
					objectInputStream.read(secretKeyInByte);
					decifraSeguro(secretKeyInByte, objectInputStream, fileName);

					System.out.println("A verificar assinatura do ficheiro " + fileName);

					// download signed file
					File signedFile = saveFile(objectInputStream);
					if (signedFile == null) {
						System.err.println("Error saving signedFile");
						continue;
					}

					// download the original signature file
					File signatureFile = saveFile(objectInputStream);
					if (signatureFile == null) {
						System.err.println("Error saving signatureFile");
						continue;
					}

					String[] parts = signatureFile.getName().split("\\.");
					String medico = parts[parts.length - 1];

					// get original signature
					byte[] originalSignature = new byte[256];
					FileInputStream originalSignatureFis = new FileInputStream(CLIENT_FOLDER + signatureFile.getName());
					originalSignatureFis.read(originalSignature);
					originalSignatureFis.close();

					// Obtain certificate
					KeyStore keyStore = getClientKeyStore(medico);
					Certificate clientCertificate = getCerfiticateFromKeyStore(medico, keyStore);
					Signature newSignature = Signature.getInstance("SHA256withRSA");
					newSignature.initVerify(clientCertificate);

					FileInputStream signedFis = new FileInputStream(CLIENT_FOLDER + signedFile.getName());

					byte[] buffer = new byte[1024];
					int bytesRead = signedFis.read(buffer);
					while (bytesRead != -1) {
						newSignature.update(buffer, 0, bytesRead);
						bytesRead = signedFis.read(buffer);
					}
					signedFis.close();

					boolean fileIsValid = newSignature.verify(originalSignature);

					if (fileIsValid) {
						System.out.println("Assinatura do ficheiro " + fileName + " é valida.");
					} else {
						System.out.println("Assinatura do ficheiro " + fileName + " não é valida.");
					}

					// delete the originalSignature and SignedFile
					signedFile.delete();
					signatureFile.delete();

				} else if (cipheredExists) {
					System.out.println("Only .cifrado file exists.");

					// decifrar
					byte[] secretKeyInByte = new byte[256];
					objectInputStream.read(secretKeyInByte);
					decifra(secretKeyInByte, objectInputStream, fileName);

				} else if (securedCipheredExists) {
					System.out.println("Only .seguro file exists.");

					// decifrar o ficheiro .seguro
					byte[] secretKeyInByte = new byte[256];
					objectInputStream.read(secretKeyInByte);
					decifra(secretKeyInByte, objectInputStream, fileName);

				} else if (signedExists) {

					System.out.println("A verificar assinatura do ficheiro " + fileName);
					// verificar assinatura

					// download signed file
					File signedFile = saveFile(objectInputStream);
					if (signedFile == null) {
						System.err.println("Error saving signedFile");
						continue;
					}

					// download the original signature file
					File signatureFile = saveFile(objectInputStream);
					if (signatureFile == null) {
						System.err.println("Error saving signatureFile");
						continue;
					}

					String[] parts = signatureFile.getName().split("\\.");
					String medico = parts[parts.length - 1];

					// get original signature
					byte[] originalSignature = new byte[256];
					FileInputStream originalSignatureFis = new FileInputStream(CLIENT_FOLDER + signatureFile.getName());
					originalSignatureFis.read(originalSignature);
					originalSignatureFis.close();

					// Obtain certificate
					KeyStore keyStore = getClientKeyStore(medico);
					Certificate clientCertificate = getCerfiticateFromKeyStore(medico, keyStore);
					Signature newSignature = Signature.getInstance("SHA256withRSA");
					newSignature.initVerify(clientCertificate);

					FileInputStream signedFis = new FileInputStream(CLIENT_FOLDER + signedFile.getName());

					byte[] buffer = new byte[1024];
					int bytesRead = signedFis.read(buffer);
					while (bytesRead != -1) {
						newSignature.update(buffer, 0, bytesRead);
						bytesRead = signedFis.read(buffer);
					}
					signedFis.close();

					boolean fileIsValid = newSignature.verify(originalSignature);

					if (fileIsValid) {
						System.out.println("Assinatura do ficheiro " + fileName + " é valida.");
					} else {
						System.out.println("Assinatura do ficheiro " + fileName + " não é valida.");
					}

					// delete the originalSignature and SignedFile
					signedFile.delete();
					signatureFile.delete();

				} else {
					System.err.println("File " + fileName + " does not exist remotely");
				}

			}
		} catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException
				| SignatureException e) {
			e.printStackTrace();
		}
	}

	private KeyStore getClientKeyStore(String client) {
		File file = new File(CLIENT_FOLDER + client + ".keystore");
		KeyStore keyStore = null;
		try (FileInputStream fileInputStream = new FileInputStream(file)) {
			keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(fileInputStream, KEYSTORE_PASSWORD.toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			System.err.println("Error getting client keyStore");
			e.printStackTrace();
		}
		return keyStore;
	}

	private Certificate getCerfiticateFromKeyStore(String client, KeyStore keyStore) {
		try {
			return (Certificate) keyStore.getCertificate(client);
		} catch (KeyStoreException e) {
			System.err.println("Could not retrieve the key for alias: " + client);
			e.printStackTrace();
			return null;
		}
	}

	private File saveFile(ObjectInputStream inStream) throws IOException {
		try {
			String fileName = (String) inStream.readObject();
			long fileSize = inStream.readLong();

			File file = new File(CLIENT_FOLDER + fileName);

			byte[] buffer = new byte[1024];
			long bytesRead = 0;
			try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
				while (bytesRead < fileSize) {
					int read = inStream.read(buffer, 0, buffer.length);
					fileOutputStream.write(buffer, 0, read);
					bytesRead += read;
				}
			}
			return file;
		} catch (IOException | ClassNotFoundException e) {
			System.err.println("Error saving file");
			e.printStackTrace();
		}
		return null;
	}

	private void decifra(byte[] encryptedAESKey, ObjectInputStream inStream, String fileName) {
		try {
			// Check if the deciphered file already exists
			File decryptedFile = new File(CLIENT_FOLDER + fileName + utente);
			if (decryptedFile.exists()) {
				System.out.println("O ficheiro decifrado já existe localmente.");
			} else {
				// CHAVE DECIFRADA!!!!

				byte[] keyEncoded = new byte[256];
				FileInputStream kfile = new FileInputStream(
						"ficheiros/servidor/" + utente + "/" + fileName + ".chave_secreta." + utente);
				kfile.read(keyEncoded);
				kfile.close();

				// decifrar a chave lida do .chave_secreta com a chave privada da mariana que
				// está no keystore
				FileInputStream kfile1 = new FileInputStream(CLIENT_FOLDER + utente + ".keystore");
				KeyStore kstore = KeyStore.getInstance("PKCS12");
				kstore.load(kfile1, "123456".toCharArray());

				Key myPrivateKey = kstore.getKey(utente, "123456".toCharArray());

				// 2. decifra a chaves AES com a chave privada
				Cipher c1 = Cipher.getInstance("RSA");
				c1.init(Cipher.UNWRAP_MODE, myPrivateKey);

				Key aesKey = c1.unwrap(keyEncoded, "AES", Cipher.SECRET_KEY);

				Cipher c2 = Cipher.getInstance("AES");
				c2.init(Cipher.DECRYPT_MODE, aesKey);

				Cipher decryptCipher = Cipher.getInstance("AES");
				decryptCipher.init(Cipher.DECRYPT_MODE, aesKey);

				System.out.println("Chave AES decifrada com sucesso.");

				FileInputStream encryptedFileStream = new FileInputStream(
						"ficheiros/servidor/" + utente + "/" + fileName + ".cifrado");
				FileOutputStream decryptedFileStream = new FileOutputStream(CLIENT_FOLDER + fileName + "." + utente + ".decifrado");

				// Create a buffer to hold chunks of data
				byte[] buffer = new byte[1024];
				int bytesRead;

				while ((bytesRead = encryptedFileStream.read(buffer)) != -1) {
					byte[] decryptedBytes = decryptCipher.update(buffer, 0, bytesRead);
					if (decryptedBytes != null) {
						decryptedFileStream.write(decryptedBytes);
					}
				}

				// Finalize the decryption process
				byte[] finalDecryptedBytes = decryptCipher.doFinal();
				if (finalDecryptedBytes != null) {
					decryptedFileStream.write(finalDecryptedBytes);
				}

				// Close the streams
				encryptedFileStream.close();
				decryptedFileStream.close();

				System.out.println("File " + fileName + " decrypted successfully.");
			}
		} catch (Exception e) {
			// Handle exceptions
			System.out.println(e);
		}

	}
	
	private void decifraSeguro(byte[] encryptedAESKey, ObjectInputStream inStream, String fileName) {
		try {
			// Check if the deciphered file already exists
			File decryptedFile = new File(CLIENT_FOLDER + fileName + utente);
			if (decryptedFile.exists()) {
				System.out.println("O ficheiro decifrado já existe localmente.");
			} else {
				// CHAVE DECIFRADA!!!!

				byte[] keyEncoded = new byte[256];
				FileInputStream kfile = new FileInputStream(
						"ficheiros/servidor/" + utente + "/" + fileName + ".chave_secreta." + utente);
				kfile.read(keyEncoded);
				kfile.close();

				// decifrar a chave lida do .chave_secreta com a chave privada da mariana que
				// está no keystore
				FileInputStream kfile1 = new FileInputStream(CLIENT_FOLDER + utente + ".keystore");
				KeyStore kstore = KeyStore.getInstance("PKCS12");
				kstore.load(kfile1, "123456".toCharArray());

				Key myPrivateKey = kstore.getKey(utente, "123456".toCharArray());

				// 2. decifra a chaves AES com a chave privada
				Cipher c1 = Cipher.getInstance("RSA");
				c1.init(Cipher.UNWRAP_MODE, myPrivateKey);

				Key aesKey = c1.unwrap(keyEncoded, "AES", Cipher.SECRET_KEY);

				Cipher c2 = Cipher.getInstance("AES");
				c2.init(Cipher.DECRYPT_MODE, aesKey);

				Cipher decryptCipher = Cipher.getInstance("AES");
				decryptCipher.init(Cipher.DECRYPT_MODE, aesKey);

				System.out.println("Chave AES decifrada com sucesso.");

				FileInputStream encryptedFileStream = new FileInputStream(
						"ficheiros/servidor/" + utente + "/" + fileName + ".cifrado");
				FileOutputStream decryptedFileStream = new FileOutputStream(CLIENT_FOLDER + fileName + "." + utente + ".decifrado");

				// Create a buffer to hold chunks of data
				byte[] buffer = new byte[1024];
				int bytesRead;

				while ((bytesRead = encryptedFileStream.read(buffer)) != -1) {
					byte[] decryptedBytes = decryptCipher.update(buffer, 0, bytesRead);
					if (decryptedBytes != null) {
						decryptedFileStream.write(decryptedBytes);
					}
				}

				// Finalize the decryption process
				byte[] finalDecryptedBytes = decryptCipher.doFinal();
				if (finalDecryptedBytes != null) {
					decryptedFileStream.write(finalDecryptedBytes);
				}

				// Close the streams
				encryptedFileStream.close();
				decryptedFileStream.close();

				System.out.println("File " + fileName + " decrypted successfully.");
			}
		} catch (Exception e) {
			// Handle exceptions
			System.out.println(e);
		}

	}
}
