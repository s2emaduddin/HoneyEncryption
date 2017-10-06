package com.src.project;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.NumberFormat;

import javax.crypto.Cipher;

public class RSAEncryption {

	/**
	 * String to hold name of the encryption algorithm.
	 */
	public static final String ALGORITHM = "RSA";

	/**
	 * String to hold the name of the private key file.
	 */
	public static final String PRIVATE_KEY_FILE = "C:\\Users\\Emad\\Desktop\\TermProject\\private.key";

	/**
	 * String to hold name of the public key file.
	 */
	public static final String PUBLIC_KEY_FILE = "C:\\Users\\Emad\\Desktop\\TermProject\\public.key";

	/**
	 * Generate key which contains a pair of private and public key using 1024
	 * bytes. Store the set of keys in Prvate.key and Public.key files.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	public static void generateKey() {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			keyGen.initialize(1024);
			final KeyPair key = keyGen.generateKeyPair();

			File privateKeyFile = new File(PRIVATE_KEY_FILE);
			File publicKeyFile = new File(PUBLIC_KEY_FILE);

			// Create files to store public and private key
			if (privateKeyFile.getParentFile() != null) {
				privateKeyFile.getParentFile().mkdirs();
			}
			privateKeyFile.createNewFile();

			if (publicKeyFile.getParentFile() != null) {
				publicKeyFile.getParentFile().mkdirs();
			}
			publicKeyFile.createNewFile();

			// Saving the Public key in a file
			ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
			publicKeyOS.writeObject(key.getPublic());
			publicKeyOS.close();

			// Saving the Private key in a file
			ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
			privateKeyOS.writeObject(key.getPrivate());
			privateKeyOS.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * The method checks if the pair of public and private key has been
	 * generated.
	 * 
	 * @return flag indicating if the pair of keys were generated.
	 */
	public static boolean areKeysPresent() {

		File privateKey = new File(PRIVATE_KEY_FILE);
		File publicKey = new File(PUBLIC_KEY_FILE);

		if (privateKey.exists() && publicKey.exists()) {
			return true;
		}
		return false;
	}

	/**
	 * Encrypt the plain text using public key.
	 * 
	 * @param text
	 *            : original plain text
	 * @param key
	 *            :The public key
	 * @return Encrypted text
	 * @throws java.lang.Exception
	 */
	public static byte[] encrypt(String text, PublicKey key) {
		byte[] cipherText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	/**
	 * Decrypt text using private key.
	 * 
	 * @param text
	 *            :encrypted text
	 * @param key
	 *            :The private key
	 * @return plain text
	 * @throws java.lang.Exception
	 */
	public static String decrypt(byte[] text, PrivateKey key) {
		byte[] dectyptedText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);

			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, key);
			dectyptedText = cipher.doFinal(text);

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return new String(dectyptedText);
	}

	/**
	 * Test the EncryptionUtil
	 */

	public String calcExecutionTime() {
		// TODO Auto-generated method stub

		BufferedReader bufferedReader = null;
		FileReader fileReader = null;

		double executionTime = 0.0;
		double exeTime = 0.0;
		try {

			// Check if the pair of keys are present else generate those.
			if (!areKeysPresent()) {
				// Method generates a pair of keys using the RSA algorithm and
				// stores it
				// in their respective files
				generateKey();
			}
			fileReader = new FileReader("C:\\Users\\Emad\\Desktop\\TermProject\\messages.txt");
			bufferedReader = new BufferedReader(fileReader);

			String originalText = null;
			ObjectInputStream inputStream = null;
			while ((originalText = bufferedReader.readLine()) != null) {

				// Encrypt the string using the public key
				inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
				final PublicKey publicKey = (PublicKey) inputStream.readObject();
				double startTime = System.currentTimeMillis();
				final byte[] cipherText = encrypt(originalText, publicKey);

				// Decrypt the cipher text using the private key.
				inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
				final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
				final String plainText = decrypt(cipherText, privateKey);
				double endTime = System.currentTimeMillis();
				double totalTime = Math.round(endTime - startTime);
				double timeInMinutes = (totalTime / 1000);
				executionTime = Math.round(timeInMinutes * 10000.0) / 10000.0;
				double d = executionTime;
				NumberFormat nf = NumberFormat.getInstance();
				nf.setMaximumFractionDigits(Integer.MAX_VALUE);
				String time = nf.format(d);
				exeTime = Double.parseDouble(time);

			}

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				bufferedReader.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return String.valueOf(exeTime);
	}
}
