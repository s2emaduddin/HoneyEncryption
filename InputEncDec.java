package com.src.project;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

// add session management to the project

public class InputEncDec {

	private String key;

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	private String method;
	private String message;

	public static String ERROR_MESSAGE = "Please enter a message of at least 5 characters";
	public static String ERROR_MSG_PWD = "Please enter a password as key to be at least of 8 characters";
	public static String CIPHER_TEXT = null;
	public static HashMap<String, Double> msgProb = new HashMap<String, Double>();
	public static ArrayList<StringBuilder> seeds = new ArrayList<StringBuilder>();
	public static HashMap<StringBuilder, String> seedToMsg = new HashMap<StringBuilder, String>();
	public static HashMap<byte[], StringBuilder> keyToSeed = new HashMap<byte[], StringBuilder>();
	public static Map<String, String> sortedSeedToMsg = new LinkedHashMap<String, String>();
	public static String originalMessage = null;
	public static HashMap<String, String> messageToSeed = new HashMap<String, String>();
	public static HashMap<String, String> cipherAndKeyStore = new HashMap<String, String>();

	public InputEncDec(String key, String method, String message) {

		this.key = key;
		this.method = method;
		this.message = message;
	}

	private static boolean bitOf(char in) {
		return (in == '1');
	}

	private static char charOf(boolean in) {
		return (in) ? '1' : '0';
	}

	public String encrypt(String message2, String key2) {
		// TODO Auto-generated method stub

		// This method is used to encrypt the input text given in the first page
		// It in turn calls several other methods in order to do the process of
		// Honey Encryption
		String keys = null;
		ArrayList<String> messages = new ArrayList<String>();

		byte[] key = null;
		String output = null;
		if (message2.length() >= 5)
			msgProb = calcMessageProbability(message2);
		else {
			output = ERROR_MESSAGE;
		}
		seeds = generateSeedSpace();
		seedToMsg = generator(seeds, msgProb);
		if (key2.length() >= 8) {
			key = createKeyFromText(key2);
		} else {
			output = ERROR_MSG_PWD;
		}
		keyToSeed = mapKeyToSeeds(seeds, key);
		HashMap<String, String> seedString = new HashMap<String, String>();
		for (Map.Entry<StringBuilder, String> entry : seedToMsg.entrySet()) {
			seedString.put(entry.getKey().toString(), entry.getValue());
		}
		sortedSeedToMsg = sortMapByValuesWithDuplicates(seedString);
		// sortedSeedToMsgNoDuplicates = createMap(sortedSeedToMsg);
		messageToSeed = inverseSampling(sortedSeedToMsg);
		// byte[] keyForStore = null;
		for (Entry<byte[], StringBuilder> e : keyToSeed.entrySet()) {
			keys = String.valueOf(e.getValue());
			// keyForStore = e.getKey();

		}

		for (Map.Entry<String, String> e : messageToSeed.entrySet()) {
			if (e.getKey().equalsIgnoreCase(getMessage())) {
				originalMessage = e.getValue();
			}
			messages.add(e.getValue());

		}
		for (int j = 0; j < messages.size(); j++) {
			StringBuilder sb = new StringBuilder();
			if (messages.get(j).equals(originalMessage)) {

				for (int i = 0; i < keys.length() && i < messages.get(j).length(); i++) {
					sb.append(charOf(bitOf(keys.charAt(i)) ^ bitOf(messages.get(j).charAt(i))));

				}
			} else {
				continue;
			}

			output = sb.toString();

		}

		CIPHER_TEXT = output;
		cipherAndKeyStore.put(CIPHER_TEXT, key2);
		return CIPHER_TEXT;
	}

	public static String checkForCorrectKey(String cipher, String key) {

		String correctMessage = cipher;
		cipher = CIPHER_TEXT;
		String output = null;
		// String keyUsed = key;
		String keyInStore = null;
		byte[] key2 = null;
		HashMap<byte[], StringBuilder> newKeyToSeed = new HashMap<byte[], StringBuilder>();
		for (Map.Entry<String, String> entry : cipherAndKeyStore.entrySet()) {
			keyInStore = entry.getValue();
			if (key.equals(keyInStore)) {
				output = correctMessage;
			} else if (!key.equals(keyInStore)) {
				key2 = createKeyFromText(key);
				newKeyToSeed = mapKeyToSeeds(seeds, key2);
				ArrayList<StringBuilder> keys = new ArrayList<StringBuilder>();
				ArrayList<String> seeds = new ArrayList<String>();

				for (Entry<byte[], StringBuilder> e : newKeyToSeed.entrySet()) {
					keys.add(e.getValue());

				}

				for (int j = 0; j < keys.size() && j < CIPHER_TEXT.length(); j++) {
					StringBuilder sb = new StringBuilder();
					for (int i = 0; i < CIPHER_TEXT.length() && i < keys.get(j).length(); i++) {
						sb.append(charOf(bitOf(keys.get(j).charAt(i)) ^ bitOf(CIPHER_TEXT.charAt(i))));
					}
					seeds.add(sb.toString());
				}
				
				 
				List<StringBuilder> keys1 = new ArrayList<StringBuilder>(seedToMsg.keySet());
				Collections.shuffle(keys1);
				for (Object o : keys1) {
					// Access keys/values in a random order
					output = seedToMsg.get(o);
					break;
				}

			}

		}
		return output;
	}

	public String decrypt() {
		// TODO Auto-generated method stub
		ArrayList<StringBuilder> keys = new ArrayList<StringBuilder>();
		ArrayList<String> seeds = new ArrayList<String>();
		String output = null;
		for (Entry<byte[], StringBuilder> e : keyToSeed.entrySet()) {
			keys.add(e.getValue());

		}

		for (int j = 0; j < keys.size() && j < CIPHER_TEXT.length(); j++) {
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < CIPHER_TEXT.length() && i < keys.get(j).length(); i++) {
				sb.append(charOf(bitOf(keys.get(j).charAt(i)) ^ bitOf(CIPHER_TEXT.charAt(i))));
			}
			seeds.add(sb.toString());
		}

		for (Entry<String, String> e : messageToSeed.entrySet()) {
			for (int i = 0; i < seeds.size(); i++) {
				if (seeds.get(i).equals(e.getValue()) && getMessage().equalsIgnoreCase(e.getKey())) {
					output = e.getKey();
					break;
				}
			}

		}
		return output;
	}

	public static ArrayList<StringBuilder> generateSeedSpace() {
		// this method generates the binary strings to map to the keys and
		// messages or the so called seed space

		int k = 1, j = 0, y = 0;
		int array[] = new int[13];
		int x = array.length - 1;
		ArrayList<StringBuilder> seeds = new ArrayList<StringBuilder>();
		StringBuilder seed = new StringBuilder();
		;
		for (int i = (int) Math.pow(2, 3); i >= 0; i--) {

			j = i;
			while (j > 0 && x >= 0) {
				k = j % 2;
				y = j / 2;
				j = y;
				array[x] = k;

				x--;
			}

			if (x != 0) {
				while (x >= 0) {
					if (x == 0) {
						array[x] = 0;
						break;
					} else {

						array[x--] = 0;

						x--;
					}

				}

			}

			for (int q = 0; q < array.length; q++) {

				seed.append(String.valueOf(array[q]));

			}
			seeds.add(seed);
			seed = new StringBuilder();
			array = new int[13];
			x = array.length - 1;
		}
		return seeds;

	}

	public static boolean checkSpecialCharacters(String message) {
		Pattern p = Pattern.compile("[^a-z0-9 ]", Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(message);
		boolean b = m.find();
		return b;
	}

	public static boolean checkNumbers(String message) {

		boolean b = false;

		if (message.matches(".*\\d.*")) {
			b = true;
		}
		return b;
	}

	public static boolean checkUpper(String message) {

		boolean hasUpper = false;

		hasUpper = !message.equals(message.toLowerCase());

		return hasUpper;
	}

	// calculating message probability

	public static HashMap<String, Double> calcMessageProbability(String message2) {

		int length = 0;
		boolean containsSpecial = false;
		boolean containsNumber = false;
		boolean containsUpper = false;
		HashMap<String, Double> messageProbability = new HashMap<String, Double>();
		if (message2.contains("12345") || message2.contains("password")) {
			messageProbability.put(message2, 0.9);
		}

		length = message2.length();
		String allLower = message2.toLowerCase();
		containsSpecial = checkSpecialCharacters(message2);
		containsNumber = checkNumbers(message2);
		containsUpper = !checkUpper(message2);

		if (length <= 10) { // length of the message to be
			// encrypted is checked
			if (message2.equals(allLower)) {
				messageProbability.put(message2, 0.99);
			} else if (containsSpecial == false && containsNumber == false && containsUpper == true) {

				messageProbability.put(message2, 0.99);
			} else if (containsSpecial == false && containsNumber == false && containsUpper == false) {
				// containsUpper will be false if the string has upper
				// case letter

				messageProbability.put(message2, 0.5);
			} else if (containsSpecial == false || containsNumber == true && containsUpper == true) {
				messageProbability.put(message2, 0.5);
			} else if (containsSpecial == false && containsNumber == true && containsUpper == false) {
				messageProbability.put(message2, 0.3);
			} else if (containsSpecial == true && containsNumber == false && containsUpper == true) {
				messageProbability.put(message2, 0.3);
			} else if (containsSpecial == true || (containsNumber == false && containsUpper == false)) { // special
																											// and
																											// Upper
																											// case
				messageProbability.put(message2, 0.2);
			} else if ((containsSpecial == true && containsNumber == true) || containsUpper == true) {
				messageProbability.put(message2, 0.2);
			} else {
				messageProbability.put(message2, 0.1);
			}

		} else if (length > 10 && length <= 15) {
			if (message2.equals(allLower)) {
				messageProbability.put(message2, 0.99);
			} else if (containsSpecial == false && containsNumber == false && containsUpper == true) {

				messageProbability.put(message2, 0.8);
			} else if (containsSpecial == false && containsNumber == false && containsUpper == false) {

				messageProbability.put(message2, 0.5);
			} else if (containsSpecial == false && containsNumber == true && containsUpper == true) {
				messageProbability.put(message2, 0.4);
			} else if (containsSpecial == false && containsNumber == true && containsUpper == false) {
				messageProbability.put(message2, 0.3);
			} else if (containsSpecial == true && containsNumber == false && containsUpper == true) {
				messageProbability.put(message2, 0.2);
			} else if (containsSpecial == true && containsNumber == false && containsUpper == false) {
				messageProbability.put(message2, 0.2);
			} else if (containsSpecial == true && containsNumber == true && containsUpper == true) {
				messageProbability.put(message2, 0.1);
			} else {
				messageProbability.put(message2, 0.1);
			}
		} else {
			if (message2.equals(allLower)) {
				messageProbability.put(message2, 0.99);
			} else {
				messageProbability.put(message2, 0.2);
			}

		}
		return messageProbability;
	}

	// create mapping between seeds and messages

	public static HashMap<StringBuilder, String> generator(ArrayList<StringBuilder> seeds,
			HashMap<String, Double> messageProb) {
		// generator creates mapping from seeds to messages based on the
		// probability of the given message being guessed
		String message = null;
		double probability = 0.0;
		int flag = 0;
		int i = 0;
		// String line = null;
		HashMap<StringBuilder, String> seedToMessage = new HashMap<StringBuilder, String>();
		for (Map.Entry<String, Double> entry : messageProb.entrySet()) {
			message = entry.getKey();
			probability = entry.getValue();

			if (probability < 0.3) {

				while (seeds.get(i) != null && flag < 2) {
					seedToMessage.put(seeds.get(i), message);
					flag++;
					i++;
				}

			}
			if (probability < 0.5 && probability >= 0.3) {
				flag = 0;
				while (seeds.get(i) != null && flag < 3) {
					if (flag > 0) {
						seedToMessage.put(seeds.get(i), getSaltString());
						flag += 1;
						i += 1;
					} else {
						seedToMessage.put(seeds.get(i), message);
						flag++;
						i++;
					}

				}
			}
			if (probability == 0.5) {
				flag = 0;
				while (seeds.get(i) != null && flag < 4) {
					if (flag > 0) {
						seedToMessage.put(seeds.get(i), getSaltString());
						flag += 1;
						i += 1;
					} else {
						seedToMessage.put(seeds.get(i), message);
						flag++;
						i++;
					}

				}
			}
			if (probability > 0.5 && probability < 0.8) {
				flag = 0;
				while (seeds.get(i) != null && flag < 5) {
					if (flag > 0) {
						seedToMessage.put(seeds.get(i), getSaltString());
						flag += 1;
						i += 1;
					} else {
						seedToMessage.put(seeds.get(i), message);
						flag++;
						i++;
					}
				}
			}
			if (probability > 0.7 && probability < 1.0) {
				flag = 0;
				while (seeds.get(i) != null && flag < 6) {
					if (flag > 0) {
						seedToMessage.put(seeds.get(i), getSaltString());
						flag += 1;
						i += 1;
					} else {
						seedToMessage.put(seeds.get(i), message);
						flag++;
						i++;
					}
				}
			}

		}
		return seedToMessage;
	}

	// generate keys from the given text as password

	public static byte[] createKeyFromText(String key2) {
		SecureRandom random = new SecureRandom();
		SecretKeyFactory skf;
		SecretKey key = null;
		byte[] keys = null;
		try {

			byte[] salt = new byte[130];
			random.nextBytes(salt);
			char[] password = key2.toCharArray();
			PBEKeySpec spec = new PBEKeySpec(password, salt, 2048, 256);
			skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			key = skf.generateSecret(spec);
			byte[] array = key.getEncoded();
			keys = array;

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return keys;

	}

	// map key to seeds

	private static HashMap<byte[], StringBuilder> mapKeyToSeeds(ArrayList<StringBuilder> seeds, byte[] key2) {
		// TODO Auto-generated method stub

		int seedsSize = seeds.size();
		Random random = new Random();
		int randomNumber = random.nextInt(seedsSize);
		HashMap<byte[], StringBuilder> keyToSeed = new HashMap<byte[], StringBuilder>();

		StringBuilder seed = seeds.get(randomNumber);
		if (seed != null && key2 != null) {

			keyToSeed.put(key2, seed);

		}
		return keyToSeed;

	}

	// sorting seedToMsg
	private static LinkedHashMap<String, String> sortMapByValuesWithDuplicates(HashMap<String, String> seedString) {
		List<String> mapKeys = new ArrayList<String>(seedString.keySet());
		List<String> mapValues = new ArrayList<String>(seedString.values());
		Collections.sort(mapValues);
		Collections.sort(mapKeys);

		LinkedHashMap<String, String> sortedMap = new LinkedHashMap<String, String>();

		Iterator<String> valueIt = mapValues.iterator();
		while (valueIt.hasNext()) {
			Object val = valueIt.next();
			Iterator<String> keyIt = mapKeys.iterator();

			while (keyIt.hasNext()) {
				Object key = keyIt.next();
				String comp1 = seedString.get(key).toString();
				String comp2 = val.toString();

				if (comp1.equals(comp2)) {
					seedString.remove(key);
					mapKeys.remove(key);
					sortedMap.put((String) key, (String) val);
					break;
				}
			}
		}
		return sortedMap;
	}

	// remove duplicate key value pairings from sorted map

	public static Map<String, String> createMap(Map<String, String> sortedSeedToMsg) {
		Map<String, String> map = new LinkedHashMap<String, String>();
		Map<String, String> tmpMap = new LinkedHashMap<String, String>();
		for (Map.Entry<String, String> entry : sortedSeedToMsg.entrySet()) {
			if (!tmpMap.containsKey(entry.getValue())) {
				tmpMap.put(entry.getValue(), entry.getKey());
			}
		}
		for (Map.Entry<String, String> entry : tmpMap.entrySet()) {
			map.put(entry.getValue(), entry.getKey());
		}

		return map;
	}

	// create inverse sampling
	// messages --> seeds
	private static HashMap<String, String> inverseSampling(Map<String, String> sortedSeedToMsg2) {

		HashMap<String, String> messageToSeed = new HashMap<String, String>();
		for (Map.Entry<String, String> entry : sortedSeedToMsg2.entrySet()) {

			messageToSeed.put(entry.getValue(), entry.getKey());
		}
		return messageToSeed;
	}

	// generate random string
	private static List<String> lines = null;
	static {
		try {
			lines = Files.readAllLines(new File("C:\\Users\\Emad\\Desktop\\TermProject\\messages.txt").toPath());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	private static Random rand = new Random();

	public static String getSaltString() {
		return lines.get(rand.nextInt(lines.size()));
	}

}
