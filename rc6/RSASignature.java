package rc6;

import java.io.BufferedReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

import javax.xml.bind.DatatypeConverter;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSASignature {
	
	// content to sign
	private static String CONTENT = HashClass.HashedTextCode;

    // private key in PKCS format
	private final static String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" + 
			"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMOvzmgA7Pnn/BYQ\n" + 
			"u1O3D9ARMWT+NePOcg2EhEfaG+DG/eA1tKq7hHt5yNQE37tFCXr041+PEHxtALAA\n" + 
			"bxYDoSCJwKqp6OF7U4tmz3BZTPY33jjNL5TS2s78T6aEQdlzYmJtvNIM1n0hold2\n" + 
			"ELULmQ0JDCjbGMPugnS1u9aLdfOJAgMBAAECgYBp0rwLcFy29KZVhGzZY8jwWyvc\n" + 
			"EsEv1afF+aDTfnbPAq2uPzzZi5ikcYKSbaRUEIyE6sO/HI3sy8GwbDumqwXJsC9A\n" + 
			"5nQZ6nlEYO6gx5734C43Xz/wwN83PBrhbPA502aMFhE1MFAGloJ2YLtc7X56D+ua\n" + 
			"GeEJZol8UQf/1oWHVQJBAPrKuT7ACHQbNchW029m0bngk1EfsUOAZVBFBVs4AT4K\n" + 
			"U9PtbK5PQWqV3yNGXVqoNF8hAxadmgAAx7XQpwXw788CQQDHwCEJWWZiLJcpXDS1\n" + 
			"fR6rS2TL/hc6ubzPQQ9unZOebsNz4sYvrTMSd1FF4mB37ouaXogshFP+8LhfYutm\n" + 
			"/6UnAkEAjP7eKK4z0nrdwNU3p8DplhPxHsGvmiCcVQWI3mDdKfEKcfJgkJsUTwUV\n" + 
			"XzKXF3nLf9QCdXuDcg7+OHSnAksTtwJAJ1hr6XiHlzzrRYVZCIqtuNXv89KH5tRh\n" + 
			"IX3SOVqmkiWFMFVx7kAyeCeyhY5yrAz7yJtoPUSPev8VggxtC+u9LwJBANxUfaJN\n" + 
			"7tRTqTQIhOSGDczR/qWsvGvmzVjOPQxpxdkeTLOFrGz/T1D4W/57Bhv2xM2H82Gi\n" + 
			"1JEGsD98evyIbQ0=\n" + 
			"-----END PRIVATE KEY-----";
			
	// public key in PKCS format
	private final static String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + 
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDr85oAOz55/wWELtTtw/QETFk\n" + 
			"/jXjznINhIRH2hvgxv3gNbSqu4R7ecjUBN+7RQl69ONfjxB8bQCwAG8WA6EgicCq\n" + 
			"qejhe1OLZs9wWUz2N944zS+U0trO/E+mhEHZc2JibbzSDNZ9IaJXdhC1C5kNCQwo\n" + 
			"2xjD7oJ0tbvWi3XziQIDAQAB\n" + 
			"-----END PUBLIC KEY-----";

    private static final String KEY_TAG_PATTERN = "-----[A-Z ]+-----";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String SHA1_WITH_RSA_ALGORITHM = "SHA1withRSA";
    
    /**
     * Signs content with the private key
     */
    public static String sign(String content, String privateKeyStr) throws GeneralSecurityException, UnsupportedEncodingException {
        PrivateKey privateKey = getPrivateKey(privateKeyStr);

        Signature signer = Signature.getInstance(SHA1_WITH_RSA_ALGORITHM);
        signer.initSign(privateKey);
        signer.update(content.getBytes(UTF_8));

        // get the signature bytes
        byte[] signatureBytes = signer.sign();

        // encode the byte array into a String
        String signature = Base64.getEncoder().encodeToString(signatureBytes);

        // encode URL characters
        signature = URLEncoder.encode(signature, UTF_8.name());
        return signature;
    }

    /**
     * Verifies content signature with the public key
     */
    public static boolean verify(String content, String signature, String publicKeyStr) throws GeneralSecurityException, UnsupportedEncodingException {
        PublicKey publicKey = getPublicKey(publicKeyStr);

        Signature verifier = Signature.getInstance(SHA1_WITH_RSA_ALGORITHM);
        verifier.initVerify(publicKey);
        verifier.update(content.getBytes(UTF_8));

        // decode URL characters
        signature = URLDecoder.decode(signature, UTF_8.name());

        // decode the the String into a byte array
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return verifier.verify(signatureBytes);
    }

    /**
     * Returns {@link PrivateKey} based on the specified private key string
     */
    private static PrivateKey getPrivateKey(String privateKeyStr) throws GeneralSecurityException {
        byte[] privateKeyBytes = keyStringToBytes(privateKeyStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
        PrivateKey privateKey = kf.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * Returns {@link PublicKey} based on the specified public key string
     */
    public static PublicKey getPublicKey(String publicKeyStr) throws GeneralSecurityException {
        byte[] publicKeyBytes = keyStringToBytes(publicKeyStr);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
        PublicKey publicKey = kf.generatePublic(keySpec);
        return publicKey;
    }

    private static byte[] keyStringToBytes(String keyString) {
        // remove unnecessary characters
        keyString = keyString
                .replaceAll(KEY_TAG_PATTERN, "")
                .replaceAll("\\s+", "");

        // decode string to base64 byte array
        return Base64.getDecoder().decode(keyString);
    }
	
    public static boolean verifyBob(String filePath) throws Exception {
    	byte[] salt = HashClass.Creating_Random_Salt();
		String valueToHash = new String(Files.readAllBytes(Paths.get(filePath)),StandardCharsets.UTF_8);;// valueToHash will the message
		byte[] hash1 = HashClass.Creating_SHA2_Hash(valueToHash, salt);
		CONTENT = DatatypeConverter.printHexBinary(hash1);
		//------------------------------
		//send hashed text to alice 
		//------------------------------

		//------------------------------
        // alice signs the hashed text
		
		String signature = sign(CONTENT, PRIVATE_KEY);// here the encryptor sings the data with his private key
		//------------------------------

		//------------------------------
        // bob verifies the signature 
		 return verify(CONTENT, signature, PUBLIC_KEY);
		//------------------------------
    }
    
    
    public static void main(String[] argv) throws Exception {
    	
    	byte[] salt = HashClass.Creating_Random_Salt(); // random slat to use in hashing
		//System.out.println("SALT_VALUE: " + DatatypeConverter.printHexBinary(salt));
		String valueToHash = new String(Files.readAllBytes(Paths.get("C:\\Users\\pc\\eclipse-workspace\\p1-gbonann1\\src\\10KB.txt")),StandardCharsets.UTF_8);;// valueToHash will the message
		System.out.println(valueToHash);
		// Generating first hash with the salt
		byte[] hash1 = HashClass.Creating_SHA2_Hash(valueToHash, salt);
		CONTENT = DatatypeConverter.printHexBinary(hash1); // content will be unknown for the encryptor  
		// Generating second hash with exact salt
		// to check if we get the same hash.
		byte[] hash2 = HashClass.Creating_SHA2_Hash(valueToHash, salt);

		// Print first and the second hash value
		System.out.println("HASH1_VALUE: " + DatatypeConverter.printHexBinary(hash1));
		System.out.println("HASH2_VALUE: " + DatatypeConverter.printHexBinary(hash2));
        String signature = sign(CONTENT, PRIVATE_KEY);// here the encryptor sings the data with his private key
        
        
        // ------------------------------------------------------------------------------
        // ------------------------------------------------------------------------------
        // send the singed content (original text hashed by the verifier) to the verifier
        // ------------------------------------------------------------------------------
        // ------------------------------------------------------------------------------
        
        
        // ------------------------------------------------------------------------------
        // ------------------------------------------------------------------------------
        // verifier receives the singed content and now he need to verify the content
        // ------------------------------------------------------------------------------
        // ------------------------------------------------------------------------------
       
        boolean isVerified = verify(CONTENT, signature, PUBLIC_KEY); 

        System.out.println("Content   : " + CONTENT);
        System.out.println("Signature : " + signature);
        System.out.println("Verified  : " + isVerified);

    }
}
