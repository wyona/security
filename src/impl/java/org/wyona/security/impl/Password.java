package org.wyona.security.impl;

import java.security.MessageDigest;
import java.security.SecureRandom;

import org.mindrot.jbcrypt.BCrypt;

/**
 * Hash a plain text password.
 * Supported algorithms are md5 (deprecated), sha256 (deprecated), and bcrypt.
 */
public class Password {

    /**
     * Hash a string using the md5 hashing algorithm.
     *
     * @param plain The plain string.
     * @return The hash, as a hexadecimal string.
     * @deprecated Use getHash(String) instead!
     */
    public static String encrypt(String plain) {
        return getMD5(plain);
    }

    /**
     * Hash a string using the md5 hashing algorithm.
     * 
     * @param plain The plain string.
     * @return The hash, as a hexadecimal string.
     * @deprecated Use getBCrypt(String) instead!
     */
    public static String getMD5(String plain) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return stringify(md.digest(plain.getBytes()));
    }

    /**
     * Hash a string using the md5 hashing algorithm, with salting.
     * 
     * @param plain The plain string.
     * @return The hash, as a hexadecimal string.
     * @deprecated Use getBCrypt(String) instead!
     */
    public static String getMD5(String plain, String salt) {
        MessageDigest md = null;
        String saltNplain = plain+salt;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return stringify(md.digest(saltNplain.getBytes()));
    }

    /**
     * Hash a string using the sha255 hashing algorithm, with salting.
     * 
     * @param plain The plain string.
     * @return The hash, as a hexadecimal string.
     * @deprecated Use getBCrypt(String) instead!
     */
    public static String getSHA256(String plain, String salt) {
        MessageDigest md = null;
        String saltNplain = plain+salt;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return stringify(md.digest(saltNplain.getBytes()));
    }
    
    /**
     * Hash a string using the bcrypt hashing algorithm.
     * 
     * @param plain The plain string.
     * @return The hash, hashed by bcrypt.
     */
    public static String getBCrypt(String plain) {
    	return BCrypt.hashpw(plain, BCrypt.gensalt(12));
    }
    
    /**
     * Verify a candidate password against a hash.
     * 
     * @param plain The plain input string.
     * @param hashed The hash of the password.
     * @return True if hash matches, false otherwise.
     */
    public static boolean verifyBCrypt(String plain, String hash) {
    	return BCrypt.checkpw(plain, hash);
    }
    
    /**
     * Generate random salt.
     * @return The salt, as a string.
     * @deprecated Use getBCrypt(String) instead!
     */
    public static String getSalt() {
        byte[] bSalt = null;
        String sSalt = null;
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            bSalt = new byte[8];	  
            sr.nextBytes(bSalt);
            sSalt = stringify(bSalt);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return sSalt;
    }

    /**
     * Converts a byte buffer to a string.
     * @param buf The buffer.
     * @return String representation of buffer (hexadecimal).
     */
    private static String stringify(byte[] buf) {
        StringBuffer sb = new StringBuffer(2 * buf.length);

        for (int i = 0; i < buf.length; i++) {
            int h = (buf[i] & 0xf0) >> 4;
            int l = (buf[i] & 0x0f);
            sb.append(new Character((char) ((h > 9) ? (('a' + h) - 10) : ('0' + h))));
            sb.append(new Character((char) ((l > 9) ? (('a' + l) - 10) : ('0' + l))));
        }

        return sb.toString();
    }
}
