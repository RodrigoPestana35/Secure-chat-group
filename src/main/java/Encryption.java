import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.*;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class represents the encryption and decryption methods.
 */
public class Encryption {

    /**
     * Generates a key pair.
     *
     * @return the key pair
     *
     * @throws NoSuchAlgorithmException if the algorithm is not available
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Encrypts a message using RSA.
     *
     * @param message the message to be encrypted
     * @param key     the key
     *
     * @return the encrypted message
     *
     * @throws Exception if an error occurs
     */
    public static byte[] encryptRSA (byte[] message, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    /**
     * Decrypts a message using RSA.
     *
     * @param message the message to be decrypted
     * @param key     the key
     *
     * @return the decrypted message
     *
     * @throws NoSuchPaddingException  if an error occurs
     * @throws NoSuchAlgorithmException if an error occurs
     * @throws InvalidKeyException if an error occurs
     * @throws IllegalBlockSizeException if an error occurs
     * @throws BadPaddingException if an error occurs
     */
    public static byte[] decryptRSA (byte[] message, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    /**
     * Encrypts a message using AES.
     *
     * @param message the message to be encrypted
     * @param key     the key
     *
     * @return the encrypted message
     *
     * @throws Exception if an error occurs
     */
    public static byte[] encryptAES(byte[] message, byte[] key) throws  Exception{
        byte[] secretKeyPadded = ByteBuffer.allocate(16).put(key).array();
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyPadded, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(message);
    }

    /**
     * Decrypts a message using AES.
     *
     * @param message the message to be decrypted
     * @param key     the key
     *
     * @return the decrypted message
     *
     * @throws Exception if an error occurs
     */
    public static byte[] decryptAES(byte[] message, byte[] key) throws  Exception{
        byte [] secretKeyPadded = ByteBuffer.allocate(16).put(key).array();
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyPadded, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(message);
    }

}
