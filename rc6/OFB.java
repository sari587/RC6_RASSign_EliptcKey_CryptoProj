package rc6;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;

public class OFB {
	private static int r = 20;
	private static int p32 = 0xB7E15163;
	private static int q32 = 0x9E3779B9;
	private static int[] S;

	private static int rotateRight(int value, int val2) {
		int retVal = (value >>> val2) | (value << (32 - val2));
		return retVal;
	}

	private static int rotateLeft(int value, int val2) {
		int retVal = (value << val2) | (value >>> (32 - val2));
		return retVal;
	}

	static byte[] encrypt(byte[] input, byte[] key) {
		S = generateKey(key);
		byte[] out = new byte[16];
		int A = (input[0] & 0xFF) | ((input[1] & 0xFF) << 8) | ((input[2] & 0xFF) << 16) | (input[3] << 24);
		int B = (input[4] & 0xFF) | ((input[5] & 0xFF) << 8) | ((input[6] & 0xFF) << 16) | (input[7] << 24);
		int C = (input[8] & 0xFF) | ((input[9] & 0xFF) << 8) | ((input[10] & 0xFF) << 16) | (input[11] << 24);
		int D = (input[12] & 0xFF) | ((input[13] & 0xFF) << 8) | ((input[14] & 0xFF) << 16) | (input[15] << 24);

		int t, u;

		B += S[0];
		D += S[1];
		for (int i = 1; i <= r; i++) {
			t = rotateLeft(B * (2 * B + 1), 5);
			u = rotateLeft(D * (2 * D + 1), 5);
			A = rotateLeft((A ^ t), u) + S[2 * i];
			C = rotateLeft((C ^ u), t) + S[2 * i + 1];
			t = A;
			A = B;
			B = C;
			C = D;
			D = t;
		}
		A += S[2 * r + 2];
		C += S[2 * r + 3];

		out[0] = (byte) A;
		out[1] = (byte) (A >>> 8);
		out[2] = (byte) (A >>> 16);
		out[3] = (byte) (A >>> 24);

		out[4] = (byte) B;
		out[5] = (byte) (B >>> 8);
		out[6] = (byte) (B >>> 16);
		out[7] = (byte) (B >>> 24);

		out[8] = (byte) C;
		out[9] = (byte) (C >>> 8);
		out[10] = (byte) (C >>> 16);
		out[11] = (byte) (C >>> 24);

		out[12] = (byte) D;
		out[13] = (byte) (D >>> 8);
		out[14] = (byte) (D >>> 16);
		out[15] = (byte) (D >>> 24);
		return out;

	}

	static byte[] decrypt(byte[] input, byte[] key) {
		S = generateKey(key);
		byte[] out = new byte[16];
		int A = (input[0] & 0xFF) | ((input[1] & 0xFF) << 8) | ((input[2] & 0xFF) << 16) | (input[3] << 24);
		int B = (input[4] & 0xFF) | ((input[5] & 0xFF) << 8) | ((input[6] & 0xFF) << 16) | (input[7] << 24);
		int C = (input[8] & 0xFF) | ((input[9] & 0xFF) << 8) | ((input[10] & 0xFF) << 16) | (input[11] << 24);
		int D = (input[12] & 0xFF) | ((input[13] & 0xFF) << 8) | ((input[14] & 0xFF) << 16) | (input[15] << 24);

		int t, u;

		C -= S[2 * r + 3];
		A -= S[2 * r + 2];
		for (int i = r; i >= 1; i--) {

			t = D;
			D = C;
			C = B;
			B = A;
			A = t;

			u = rotateLeft(D * (2 * D + 1), 5);
			t = rotateLeft(B * (2 * B + 1), 5);
			C = rotateRight(C - S[2 * i + 1], t) ^ u;
			A = rotateRight(A - S[2 * i], u) ^ t;

		}
		D -= S[1];
		B -= S[0];

		out[0] = (byte) A;
		out[1] = (byte) (A >>> 8);
		out[2] = (byte) (A >>> 16);
		out[3] = (byte) (A >>> 24);

		out[4] = (byte) B;
		out[5] = (byte) (B >>> 8);
		out[6] = (byte) (B >>> 16);
		out[7] = (byte) (B >>> 24);

		out[8] = (byte) C;
		out[9] = (byte) (C >>> 8);
		out[10] = (byte) (C >>> 16);
		out[11] = (byte) (C >>> 24);

		out[12] = (byte) D;
		out[13] = (byte) (D >>> 8);
		out[14] = (byte) (D >>> 16);
		out[15] = (byte) (D >>> 24);
		return out;
	}

	private static int[] generateKey(byte[] userKey) {
		int c = userKey.length / 4;
		int sizeOfS = 2 * r + 4;

		int[] S = new int[sizeOfS];

		int[] L = new int[c];
		int off = 0;
		for (int i = 0; i < c; i++)
			L[i] = (userKey[off++] & 0xFF) | ((userKey[off++] & 0xFF) << 8) | ((userKey[off++] & 0xFF) << 16)
					| ((userKey[off++] & 0xFF) << 24);

		S[0] = p32;
		for (int i = 1; i < sizeOfS; i++) {
			S[i] = S[i - 1] + q32;
		}
		int val1 = 0;
		int val2 = 0;
		int i = 0;
		int j = 0;
		int v = 3 * Math.max(c, sizeOfS);

		for (int k = 0; k < v; k++) {
			val1 = S[i] = rotateLeft((S[i] + val1 + val2), 3);
			val2 = L[j] = rotateLeft(L[j] + val1 + val2, val1 + val2);
			i = (i + 1) % sizeOfS;
			j = (j + 1) % c;

		}
		return S;

	}

	public static String usingBufferedReader(String filePath) {
		String CurrentLine;
		String AllData = "";
		try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {

			while ((CurrentLine = br.readLine()) != null) {
				AllData = AllData + CurrentLine + "ó";
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			System.out.println("Plase enter rigth path for file in code line 120");
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return AllData;
	}

	public static byte[] hexStringToByteArray(String hex) {
		int l = hex.length();
		byte[] data = new byte[l / 2];
		for (int i = 0; i < l; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		}
		return data;
	}

	public static String convert_string_to_hex(String text) {

		char[] chArray = text.toCharArray();
		String strHexadecimal = "";
		for (int a = 0; a < chArray.length; a++) {
			strHexadecimal = strHexadecimal + Integer.toHexString(chArray[a]);
		}
		return strHexadecimal;
	}

	public static String xorHex(String a, String b) {
		// TODO: Validation
		char[] chars = new char[a.length()];
		for (int i = 0; i < chars.length; i++) {
			chars[i] = toHex(fromHex(a.charAt(i)) ^ fromHex(b.charAt(i)));
		}
		return new String(chars);
	}

	private static int fromHex(char c) {
		if (c >= '0' && c <= '9') {
			return c - '0';
		}
		if (c >= 'A' && c <= 'F') {
			return c - 'A' + 10;
		}
		if (c >= 'a' && c <= 'f') {
			return c - 'a' + 10;
		}
		throw new IllegalArgumentException();
	}

	private static char toHex(int nybble) {
		if (nybble < 0 || nybble > 15) {
			throw new IllegalArgumentException();
		}
		return "0123456789ABCDEF".charAt(nybble);
	}

	public static void main(String[] args) throws Exception {

		// Alice wants to send message to Bob
		// _____________________________________

		// -------------------------------------
		// -------------------------------------
		// Step 1 : Alice encrypts the message
		// -------------------------------------
		// -------------------------------------

		// Step 1.1 : initialization of parameters
		ArrayList<String> splitedText = new ArrayList<String>();
		ArrayList<String> splitedEncreptedText = new ArrayList<String>();
		ArrayList<String> spliteDecryptedText = new ArrayList<String>();
		byte[] IVtext = new byte[16];
		byte[] ciphertext = new byte[16];
		byte[] userKey = null;
		byte[] result;
		byte[] bytes;
		String[] arr;
		String encreptid = "";
		String encreptid2 = "";
		String freeToUseStr = "";
		String key, IV, prevIV;
		String st, finalStr = "";
		String filePath;
		String plainTextFROmUser;

		// 16 byte initialized vector (IV) agreed on by both parties (Alice + Bob) there
		// is no need to be private as per Kerckhoffs's principle
		IV = "20 61 62 63 64 61 62 63 64 61 62 63 64 61 62 63 64";
		String[] tokens = IV.split("\\s+");
		for (int i = 0; i < IVtext.length; i++) {
			if (i < 16) {
				IVtext[i] = (byte) Integer.parseInt(tokens[i + 1], 16);
			} else
				break;
		}

		// the key for encryption can be altered however ALice wishes to
		key = "01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67";
		tokens = key.split("\\s+");
		userKey = new byte[tokens.length - 1];
		for (int i = 0; i < userKey.length; i++) {
			userKey[i] = (byte) Integer.parseInt(tokens[i + 1], 16);
		}

		// Step 1.2 : get the file to encrypt + save it in blocks of 8 bytes
		
		filePath = "C:\\Users\\pc\\eclipse-workspace\\p1-gbonann1\\src\\1MB.txt";
		plainTextFROmUser = convert_string_to_hex(OFB.usingBufferedReader(filePath));
		int index = 0;
		while (index < plainTextFROmUser.length()) {
			splitedText.add(plainTextFROmUser.substring(index, Math.min(index + 16, plainTextFROmUser.length())));
			index += 16;
		}

		// Handling the last block
		if (splitedText.get(splitedText.size() - 1).length() != 16) { // if last block isn't 8 bytes
			freeToUseStr = splitedText.get(splitedText.size() - 1);
			splitedText.remove(splitedText.size() - 1); // remove from block list
			while (freeToUseStr.length() != 16) { // create a new block we fill to reach 8 bytes
				freeToUseStr = freeToUseStr + "f3"; // fill the remaining of the block with special character (f3 = ó)
			}
			splitedText.add(freeToUseStr); // add the new block to list
		}

		// encrypt with RC6 algorithm in OFB
		int j = 0;
		while (j < splitedText.size()) {
			prevIV = IV;
			// encrypt the IV
			result = encrypt(IVtext, userKey);

			for (int i = 0; i < result.length; i++) {
				if (Integer.toHexString(result[i] & 0xFF).length() == 1) {
					encreptid = encreptid + "0" + Integer.toHexString(result[i] & 0xFF);
					encreptid2 = encreptid2 + "0" + Integer.toHexString(result[i] & 0xFF) + " ";
				} else {
					encreptid = encreptid + Integer.toHexString(result[i] & 0xFF);
					encreptid2 = encreptid2 + Integer.toHexString(result[i] & 0xFF) + " ";
				}

			}
			// XOR the first 8 bytes (we chose 8 bytes it can be altered (4,16,...))
			// + save the encryption result in a list to send
			splitedEncreptedText.add(xorHex(encreptid.substring(0, 16), splitedText.get(j)));

			// new IV for next block encryption
			// IVtext = 1/2 right privIV + 1/2 lift encreptedIV

			arr = encreptid.split("");
			encreptid2 = "";
			for (int i = 0; i < arr.length / 2; i = i + 2) {
				encreptid2 = encreptid2 + arr[i] + arr[i + 1] + " ";
			}
			encreptid2 = encreptid2.substring(0, encreptid2.length() - 1);
			IV = prevIV.substring(24, prevIV.length()) + " " + encreptid2;
			tokens = IV.split("\\s+");
			encreptid = "";
			encreptid2 = "";
			for (int i = 0; i < IVtext.length; i++) {
				try {
					IVtext[i] = (byte) Integer.parseInt(tokens[i + 1], 16);
				} catch (Exception e) {

				}
			}
			j++;
		}

		// -------------------------------------
		// -------------------------------------
		// Step 2 : Alice verifies Bob
		// -------------------------------------
		// -------------------------------------
		if (!RSASignature.verifyBob(filePath)) {
			System.out.println("recevr is not Bob !!!");
			System.exit(0);
		}

		// -------------------------------------
		// -------------------------------------
		// Step 3 : Alice sends key to Bob
		// -------------------------------------
		// -------------------------------------

		// here we send the key using Elgmal with elliptic curves (python code)

		// -------------------------------------
		// -------------------------------------
		// Step 4 : Bob decrypt the massage
		// -------------------------------------
		// -------------------------------------

		// 16 byte initialized vector (IV) agreed on by both parties (Alice + Bob) there
		// is no need to be private as per Kerckhoffs's principle
		IV = "20 61 62 63 64 61 62 63 64 61 62 63 64 61 62 63 64";
		j = 0;
		tokens = IV.split("\\s+");
		for (int i = 0; i < IVtext.length; i++) {
			if (i < 16) {
				IVtext[i] = (byte) Integer.parseInt(tokens[i + 1], 16);
			} else
				break;
		}

		key = "01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67"; // the key
		tokens = key.split("\\s+");
		userKey = new byte[tokens.length - 1];
		for (int i = 0; i < userKey.length; i++) {
			userKey[i] = (byte) Integer.parseInt(tokens[i + 1], 16);
		}

		while (j < splitedEncreptedText.size()) {
			prevIV = IV;
			// encrypt the IV
			result = encrypt(IVtext, userKey);

			for (int i = 0; i < result.length; i++) {
				if (Integer.toHexString(result[i] & 0xFF).length() == 1) {
					encreptid = encreptid + "0" + Integer.toHexString(result[i] & 0xFF);
					encreptid2 = encreptid2 + "0" + Integer.toHexString(result[i] & 0xFF) + " ";
				} else {
					encreptid = encreptid + Integer.toHexString(result[i] & 0xFF);
					encreptid2 = encreptid2 + Integer.toHexString(result[i] & 0xFF) + " ";
				}

			}

			// XOR the first 16 bytes (we chose 16 bytes it can be altered (4,8,...))
			// + save the encryption result in a list to send
			spliteDecryptedText.add(xorHex(encreptid.substring(0, 16), splitedEncreptedText.get(j)));

			// new IV for next encryption
			// IVtext = 1/2 right privIV + 1/2 lift encreptedIV

			arr = encreptid.split("");
			encreptid2 = "";
			for (int i = 0; i < arr.length / 2; i = i + 2) {
				encreptid2 = encreptid2 + arr[i] + arr[i + 1] + " ";
			}

			encreptid2 = encreptid2.substring(0, encreptid2.length() - 1);
			IV = prevIV.substring(24, prevIV.length()) + " " + encreptid2;

			tokens = IV.split("\\s+");
			encreptid = "";
			encreptid2 = "";
			for (int i = 0; i < IVtext.length; i++) {
				try {
					IVtext[i] = (byte) Integer.parseInt(tokens[i + 1], 16);
				} catch (Exception e) {

				}
			}
			j++;
		}

		// to decrypt we XOR the cipher text with IV
		for (int i = 0; i < spliteDecryptedText.size(); i++) {
			if (i != spliteDecryptedText.size() - 1) {
				freeToUseStr = spliteDecryptedText.get(i).replace("F3", "0d0a");
				bytes = hexStringToByteArray(freeToUseStr);
				st = new String(bytes, StandardCharsets.UTF_8);
				finalStr = finalStr + st;
			} else {
				freeToUseStr = spliteDecryptedText.get(i);
				if (freeToUseStr.substring(freeToUseStr.length() - 2, freeToUseStr.length()).equals("F3")) {
					freeToUseStr = freeToUseStr.replace("F3", "");
				}
				bytes = hexStringToByteArray(freeToUseStr);
				st = new String(bytes, StandardCharsets.UTF_8);
				finalStr = finalStr + st;
			}
		}

		System.out.println(finalStr);

	}

}
