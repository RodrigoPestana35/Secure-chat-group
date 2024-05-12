import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * This class represents the integrity methods.
 */
public class Integrity {

    /**
     * Generates a digest.
     *
     * @param message the message to be digested
     *
     * @return the digest
     *
     * @throws Exception if an error occurs
     */
    public static byte[] generateDigest(byte[] message) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
        return messageDigest.digest(message);
    }

    /**
     * Verifies the digest.
     *
     * @param digest the digest
     * @param computeDigest the computed digest
     *
     * @return true if the digest is verified, false otherwise
     */
    public static boolean verifyDigest(byte[] digest, byte[] computeDigest){
        return Arrays.equals(digest, computeDigest);
    }

}
