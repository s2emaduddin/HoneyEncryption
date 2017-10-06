package com.src.project;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
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
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class HoneyEncryption {

	public static ArrayList<byte[]> keys = new ArrayList<byte[]>();
	public static HashMap<byte[], String> keyToSeed = new HashMap<byte[], String>();
	public static HashMap<String, String> messageToSeed = new HashMap<String, String>();
	public static ArrayList<String> CIPHER_TEXT = new ArrayList<String>();
	public static ArrayList<String> DECIPHERED = new ArrayList<String>();
	public static HashMap<String, String> seedToMsg = new HashMap<String, String>();
	public static Map<String, String> sortedSeedToMsg = new LinkedHashMap<String, String>();
	public static Map<String, String> sortedSeedToMsgNoDuplicates = new LinkedHashMap<String, String>();
	public static HashMap<String, Double> messageProb = new HashMap<String, Double>();
	public static StringBuilder output = new StringBuilder();
	public static PrintWriter writer = null;
	public static String COMMA_DELIMITER = ",";

	/*
	 * public static void main(String[] args) {
	 * 
	 * double exeTime = calcExecutionTime(); }
	 */

	public static void createCSV() {

		try {
			writer = new PrintWriter(new File("C:\\Users\\Emad\\Desktop\\TermProject\\output.csv"));

			ArrayList<String> originalMessages = new ArrayList<String>();
			for (Map.Entry<String, String> e : messageToSeed.entrySet()) {
				originalMessages.add(e.getKey());

			}
			output.append("Original Message");
			output.append(COMMA_DELIMITER);
			output.append("Encrypted Message");
			output.append(COMMA_DELIMITER);
			output.append("Decrypted Message");
			output.append("\n");
			writer.print(output);
			for (int i = 0, j = 0, k = 0; i < originalMessages.size() && j < CIPHER_TEXT.size()
					&& k < DECIPHERED.size(); i++, j++, k++) {
				output = new StringBuilder();
				output.append(originalMessages.get(i));
				output.append(COMMA_DELIMITER);
				output.append(CIPHER_TEXT.get(j));
				output.append(COMMA_DELIMITER);
				output.append(DECIPHERED.get(k));
				output.append("\n");
				writer.print(output);
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			writer.close();
		}

	}

	public String calcExecutionTime() {

		double executionTime = 0.0;
		double startTime = System.currentTimeMillis();

		encrypt();
		decrypt();
		double endTime = System.currentTimeMillis();

		double totalTime = Math.round(endTime - startTime);
		double timeInMinutes = (totalTime / 1000);
		executionTime = Math.round(timeInMinutes * 10000.0) / 10000.0;
		createCSV();
		return String.valueOf(executionTime);
	}

	private static boolean bitOf(char in) {
		return (in == '1');
	}

	private static char charOf(boolean in) {
		return (in) ? '1' : '0';
	}

	private static void creation() {

		try {

			generateSeedSpace();
			FileReader fileReader = new FileReader("C:\\Users\\Emad\\Desktop\\TermProject\\messages.txt");
			FileReader fileReader1 = new FileReader("C:\\Users\\Emad\\Desktop\\TermProject\\seed1.txt");
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			BufferedReader bufferedReader1 = new BufferedReader(fileReader1);
			messageProb = calcMessageProbability(bufferedReader);
			seedToMsg = generator(bufferedReader1, messageProb);

			createKeyFromText();
			mapKeyToSeeds(bufferedReader1, keys);
			sortedSeedToMsg = sortMapByValuesWithDuplicates(seedToMsg);
			sortedSeedToMsgNoDuplicates = createMap(sortedSeedToMsg);
			inverseSampling(sortedSeedToMsgNoDuplicates);

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void encrypt() {
		// TODO Auto-generated method stub

		creation();
		ArrayList<String> keys = new ArrayList<String>();
		ArrayList<String> messages = new ArrayList<String>();
		for (Map.Entry<byte[], String> e : keyToSeed.entrySet()) {
			keys.add(e.getValue());

		}

		for (Map.Entry<String, String> e : messageToSeed.entrySet()) {
			messages.add(e.getValue());
			// System.out.println("The message being encrypted is " +
			// e.getKey());

		}

		for (int j = 0; j < keys.size() && j < messages.size(); j++) {
			StringBuilder sb = new StringBuilder();
			// System.out.println("The key for encryption " + keys.get(j));
			for (int i = 0; i < keys.get(j).length() && i < messages.get(j).length(); i++) {
				sb.append(charOf(bitOf(keys.get(j).charAt(i)) ^ bitOf(messages.get(j).charAt(i))));

			}

			CIPHER_TEXT.add(sb.toString());

		}

	}

	public static void decrypt() {

		// creation();
		ArrayList<String> keys = new ArrayList<String>();
		ArrayList<String> seeds = new ArrayList<String>();
		for (Map.Entry<byte[], String> e : keyToSeed.entrySet()) {
			keys.add(e.getValue());

		}

		for (int j = 0; j < keys.size() && j < CIPHER_TEXT.size(); j++) {
			StringBuilder sb = new StringBuilder();
			// System.out.println("the key for decryption: " + keys.get(j));
			for (int i = 0; i < CIPHER_TEXT.get(j).length() && i < keys.get(j).length(); i++) {
				sb.append(charOf(bitOf(keys.get(j).charAt(i)) ^ bitOf(CIPHER_TEXT.get(j).charAt(i))));
			}
			seeds.add(sb.toString());
		}

		for (Map.Entry<String, String> e : messageToSeed.entrySet()) {
			for (int i = 0; i < seeds.size(); i++) {
				if (seeds.get(i).equals(e.getValue())) {
					DECIPHERED.add(e.getKey());
					break;
				}
			}

		}
	}

	// sorting seedToMsg
	private static LinkedHashMap<String, String> sortMapByValuesWithDuplicates(Map<String, String> seedToMsg) {
		List<String> mapKeys = new ArrayList<String>(seedToMsg.keySet());
		List<String> mapValues = new ArrayList<String>(seedToMsg.values());
		Collections.sort(mapValues);
		Collections.sort(mapKeys);

		LinkedHashMap<String, String> sortedMap = new LinkedHashMap<String, String>();

		Iterator<String> valueIt = mapValues.iterator();
		while (valueIt.hasNext()) {
			Object val = valueIt.next();
			Iterator<String> keyIt = mapKeys.iterator();

			while (keyIt.hasNext()) {
				Object key = keyIt.next();
				String comp1 = seedToMsg.get(key).toString();
				String comp2 = val.toString();

				if (comp1.equals(comp2)) {
					seedToMsg.remove(key);
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
	private static void inverseSampling(Map<String, String> sortedSeedToMsg2) {

		for (Map.Entry<String, String> entry : sortedSeedToMsg2.entrySet()) {

			messageToSeed.put(entry.getValue(), entry.getKey());
			// System.out.println(entry.getValue() + "<--- this is the key
			// message and its seed is " + entry.getKey());
		}
	}

	private static void mapKeyToSeeds(BufferedReader buffReader, ArrayList<byte[]> keys) {
		// TODO Auto-generated method stub

		String line = null;
		int i = 0;
		try {
			while ((line = buffReader.readLine()) != null && i < keys.size()) {
				byte[] k = keys.get(i);
				keyToSeed.put(k, line);
				i++;
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static void createKeyFromText() {

		FileReader reader = null;
		BufferedReader buffReader = null;
		String line = null;
		SecureRandom random = new SecureRandom();
		SecretKeyFactory skf;
		SecretKey key = null;

		try {
			reader = new FileReader("C:\\Users\\Emad\\Desktop\\TermProject\\keys.txt");
			buffReader = new BufferedReader(reader);
			keys = new ArrayList<byte[]>();

			while ((line = buffReader.readLine()) != null) {
				byte[] salt = new byte[130];
				random.nextBytes(salt);
				char[] password = line.toCharArray();
				PBEKeySpec spec = new PBEKeySpec(password, salt, 2048, 256); // 2048 is the number of iterations and 256 is the key length in bits
				skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
				key = skf.generateSecret(spec);
				byte[] array = key.getEncoded();
				keys.add(array);

			}

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static void generateSeedSpace() {
		int k = 1, j = 0, y = 0;
		int array[] = new int[13];
		int x = array.length - 1;
		File file = new File("C:\\Users\\Emad\\Desktop\\TermProject\\seed1.txt");
		FileWriter output = null;
		BufferedWriter writer = null;
		PrintWriter printer = null;
		try {

			output = new FileWriter(file, true);
			writer = new BufferedWriter(output);
			printer = new PrintWriter(writer);
		} catch (IOException e) {
			e.printStackTrace();
		}

		for (int i = (int) Math.pow(2, 12); i >= 0; i--) {

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

				printer.print(array[q]);
				printer.flush();
			}
			printer.println();
			array = new int[13];
			x = array.length - 1;
		}

		printer.close();

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

	public static HashMap<String, Double> calcMessageProbability(BufferedReader bufferedReader) {

		String line = null;
		int length = 0;
		boolean containsSpecial = false;
		boolean containsNumber = false;
		boolean containsUpper = false;
		HashMap<String, Double> messageProbability = new HashMap<String, Double>();
		try {
			while ((line = bufferedReader.readLine()) != null) {

				// checking for most common strings as messages

				if (line.contains("12345678") || line.contains("password") || line.contains("iloveyou")) {
					messageProbability.put(line, 0.9);
				}

				length = line.length();
				if (length == 0) {
					break;
				}
				containsSpecial = checkSpecialCharacters(line);
				containsNumber = checkNumbers(line);
				containsUpper = !checkUpper(line);
				if (length < 5) {
					break;
				} else if (length <= 10) { // length of the message to be
											// encrypted is checked

					if (containsSpecial == false && containsNumber == false && containsUpper == true) {

						messageProbability.put(line, 0.99);
					} else if (containsSpecial == false && containsNumber == false && containsUpper == false) {
						// containsUpper will be false if the string has upper
						// case letter

						messageProbability.put(line, 0.5);
					} else if (containsSpecial == false || containsNumber == true && containsUpper == true) {
						messageProbability.put(line, 0.5);
					} else if (containsSpecial == false && containsNumber == true && containsUpper == false) {
						messageProbability.put(line, 0.3);
					} else if (containsSpecial == true && containsNumber == false && containsUpper == true) {
						messageProbability.put(line, 0.3);
					} else if (containsSpecial == true || (containsNumber == false && containsUpper == false)) { // special
																													// and
																													// Upper
																													// case
						messageProbability.put(line, 0.2);
					} else if ((containsSpecial == true && containsNumber == true) || containsUpper == true) {
						messageProbability.put(line, 0.2);
					} else {
						messageProbability.put(line, 0.1);
					}

				} else if (length > 10 && length <= 15) {
					if (containsSpecial == false && containsNumber == false && containsUpper == true) {

						messageProbability.put(line, 0.8);
					} else if (containsSpecial == false && containsNumber == false && containsUpper == false) {

						messageProbability.put(line, 0.5);
					} else if (containsSpecial == false && containsNumber == true && containsUpper == true) {
						messageProbability.put(line, 0.4);
					} else if (containsSpecial == false && containsNumber == true && containsUpper == false) {
						messageProbability.put(line, 0.3);
					} else if (containsSpecial == true && containsNumber == false && containsUpper == true) {
						messageProbability.put(line, 0.2);
					} else if (containsSpecial == true && containsNumber == false && containsUpper == false) {
						messageProbability.put(line, 0.2);
					} else if (containsSpecial == true && containsNumber == true && containsUpper == true) {
						messageProbability.put(line, 0.1);
					} else {
						messageProbability.put(line, 0.1);
					}
				} else {
					messageProbability.put(line, 0.2);
				}

			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return messageProbability;
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

	public static HashMap<String, String> generator(BufferedReader bufferedReader1,
			HashMap<String, Double> messageProb) {
		// generator creates mapping from seeds to messages.
		String message = null;
		Double probability = 0.0;
		FileReader fileReader = null;
		BufferedReader bufferedReader = null;
		int flag = 0;
		String line = null;
		HashMap<String, String> seedToMessage = new HashMap<String, String>();
		try {
			fileReader = new FileReader("C:\\Users\\Emad\\Desktop\\TermProject\\seed1.txt");			bufferedReader = new BufferedReader(fileReader);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		for (Map.Entry<String, Double> entry : messageProb.entrySet()) {
			message = entry.getKey();
			probability = entry.getValue();

			if (probability < 0.3) {

				try {
					while ((line = bufferedReader.readLine()) != null && flag < 2) {

						seedToMessage.put(line, message);
						flag++;
					}

				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}
			if (probability < 0.5) {
				flag = 0;
				try {
					while ((line = bufferedReader.readLine()) != null && flag < 2) {
						seedToMessage.put(line, message);
						flag++;
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			if (probability == 0.5) {
				flag = 0;
				try {
					while ((line = bufferedReader.readLine()) != null && flag < 3) {
						seedToMessage.put(line, message);
						flag++;
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			if (probability > 0.5 && probability < 0.8) {
				flag = 0;
				try {
					while ((line = bufferedReader.readLine()) != null && flag < 4) {
						seedToMessage.put(line, message);
						flag++;
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			if (probability > 0.7 && probability < 1.0) {
				flag = 0;
				try {
					while ((line = bufferedReader.readLine()) != null && flag < 5) {
						seedToMessage.put(line, message);
						flag++;
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

		}
		return seedToMessage;
	}

}
