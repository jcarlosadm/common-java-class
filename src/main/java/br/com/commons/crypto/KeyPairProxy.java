package br.com.commons.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyPairProxy {

	private PublicKey publicKey = null;
	private PrivateKey privateKey = null;

	public boolean createNewKeys(String user, String password) throws Exception {
		if (this.createKeyStore(user, password) == false)
			return false;
		
		return this.loadKeys(user, password);
	}

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

	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	public String encryptWithPublicKey(String message) throws Exception {
		// TODO implement
		return null;
	}

	public String sign(String message) throws Exception {
		// TODO implement
		return null;
	}

	public String decrypt(String message) throws Exception {
		// TODO implement
		return null;
	}

	public String encryptWithOtherPublicKey(String message, PublicKey key) throws Exception {
		// TODO implement
		return null;
	}

	public boolean verifySignWithOtherPublicKey(String message, String signature, PublicKey publicKey) {
		// TODO implement
		return false;
	}

	private boolean createKeyStore(String user, String password) throws Exception {
		if(this.keystoreExists(user) == true)
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

	public static void main(String[] args) {
		KeyPairProxy kProxy = new KeyPairProxy();
		
		try {
			System.out.println(kProxy.createNewKeys("josecarlos", "12345678"));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
