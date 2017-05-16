package br.com.commons.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;

import org.apache.commons.lang.NotImplementedException;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Interface class to create and use a pair of keys for encrypt and decrypt
 * messages. Beyond that, has one method to encrypt message with other public
 * key.
 * 
 * To create and store keys in secure storage, you will need the keytool of java.
 *
 */
public class KeyPairProxy {

	private PublicKey publicKey = null;
	private PrivateKey privateKey = null;

	/**
	 * create temporary pair of keys
	 * 
	 * @throws Exception
	 *             if fail in generate keys
	 */
	public void createNewKeys() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048, new SecureRandom());
		KeyPair pair = generator.generateKeyPair();
		this.publicKey = pair.getPublic();
		this.privateKey = pair.getPrivate();
	}

	/**
	 * create new keys and store in secure storage
	 * 
	 * @param user
	 *            alias used for key id
	 * @param password
	 *            password for secure storage
	 * @return true if case of success. false in otherwise
	 * @throws Exception
	 *             in case of fail
	 */
	public boolean createNewKeys(String user, String password) throws Exception {
		if (this.createKeyStore(user, password) == false)
			return false;

		return this.loadKeys(user, password);
	}

	/**
	 * load keys from secure storage
	 * 
	 * @param user
	 *            alias used for key id
	 * @param password
	 *            password for secure storage
	 * @return true in case of success. false in otherwise
	 * @throws Exception
	 *             in case of fail
	 */
	public boolean loadKeys(String user, String password) throws Exception {
		if (this.keystoreExists(user) == false)
			return false;

		KeyStore keyStore = KeyStore.getInstance("jceks");
		keyStore.load(new FileInputStream(user + ".jks"), password.toCharArray());
		KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(password.toCharArray());

		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(user, keyPassword);
		if (privateKeyEntry == null)
			return false;

		java.security.cert.Certificate cert = keyStore.getCertificate(user);
		if (cert == null)
			return false;

		this.publicKey = cert.getPublicKey();
		this.privateKey = privateKeyEntry.getPrivateKey();

		return true;
	}

	/**
	 * @return generated public key, or null if keys not exists yet
	 */
	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	/**
	 * encrypt message with your public key, returning an encrypted message in
	 * base64
	 * 
	 * @param message
	 *            message to be encrypted
	 * @return encrypted message in base64
	 * @throws Exception
	 *             in case of fail
	 */
	public String encryptWithPublicKey(String message) throws Exception {
		return this.encrypt(message, this.publicKey);
	}

	private String encrypt(String message, PublicKey publicKey) throws Exception {
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] cipherText = encryptCipher.doFinal(message.getBytes(UTF_8));
		return Base64.getEncoder().encodeToString(cipherText);
	}

	@SuppressWarnings("unused")
	private String sign(String message) throws Exception {
		// TODO implement
		throw new NotImplementedException();
	}

	/**
	 * decrypt message in base64
	 * 
	 * @param message
	 *            encrypted message in base64
	 * @return decrypted message
	 * @throws Exception
	 *             in case of fail
	 */
	public String decrypt(String message) throws Exception {
		byte[] bytes = Base64.getDecoder().decode(message);
		Cipher decriptCipher = Cipher.getInstance("RSA");
		decriptCipher.init(Cipher.DECRYPT_MODE, this.privateKey);

		return new String(decriptCipher.doFinal(bytes), UTF_8);
	}

	/**
	 * encrypt message with other public key, returning an encrypted message in
	 * base64
	 * 
	 * @param message
	 *            message to be encrypted
	 * @param key
	 *            public key
	 * @return encrypted message
	 * @throws Exception
	 *             in case of fail
	 */
	public String encryptWithOtherPublicKey(String message, PublicKey key) throws Exception {
		return this.encrypt(message, key);
	}

	@SuppressWarnings("unused")
	private boolean verifySignWithOtherPublicKey(String message, String signature, PublicKey publicKey) {
		// TODO implement
		throw new NotImplementedException();
	}

	private boolean createKeyStore(String user, String password) throws Exception {
		if (this.keystoreExists(user) == true)
			return true;

		ProcessBuilder processBuilder = new ProcessBuilder("keytool", "-genkeypair", "-alias", user, "-storepass",
				password, "-keypass", password, "-keyalg", "RSA", "-keystore", user + ".jks", "-noprompt", "-dname",
				"CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown");
		Process process = processBuilder.start();

		InputStream is = process.getInputStream();
		InputStreamReader isr = new InputStreamReader(is);
		BufferedReader br = new BufferedReader(isr);

		while ((br.readLine()) != null) {
		}

		boolean ok = (process.waitFor() == 0 ? true : false);

		String line;
		while ((line = br.readLine()) != null) {
			System.out.println(line);
		}

		return ok;
	}

	private boolean keystoreExists(String user) {
		return new File(user + ".jks").exists();
	}
}
