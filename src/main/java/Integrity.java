import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Integrity {

    public static byte[] generateDigest(byte[] message) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
        return messageDigest.digest(message);
    }

    public static boolean verifyDigest(byte[] digest, byte[] computeDigest){
        return Arrays.equals(digest, computeDigest);
    }

}
