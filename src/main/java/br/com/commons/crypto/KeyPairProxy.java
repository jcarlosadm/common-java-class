package br.com.commons.crypto;

import java.security.KeyPair;
import java.security.PublicKey;

public class KeyPairProxy {
	
	private KeyPair keyPair = null;
	
	
	public boolean createNewKeys(String user, String password) throws Exception {
		// TODO implement
		return false;
	}
	
	public boolean loadKeys(String user, String password) throws Exception {
		// TODO implement
		return false;
	}
	
	public PublicKey getPulicKey() {
		// TODO implement
		return null;
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
}
