import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.*;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptRSA (byte[] message, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public static byte[] decryptRSA (byte[] message, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public static byte[] encryptAES(byte[] message, byte[] key) throws  Exception{
        byte[] secretKeyPadded = ByteBuffer.allocate(16).put(key).array();
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyPadded, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(message);
    }
    public static byte[] decryptAES(byte[] message, byte[] key) throws  Exception{
        byte [] secretKeyPadded = ByteBuffer.allocate(16).put(key).array();
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyPadded, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(message);
    }

}
