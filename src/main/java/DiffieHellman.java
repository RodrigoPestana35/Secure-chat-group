import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * This class represents the Diffie-Hellman key exchange algorithm.
 */
public class DiffieHellman {


    private static final int NUM_BITS = 128;
    private static final BigInteger N = new BigInteger ( "1289971646" );
    private static final BigInteger G = new BigInteger ( "3" );

    /**
     * Generates a private key.
     *
     * @return the private key
     *
     * @throws NoSuchAlgorithmException if the algorithm is not available
     */
    public static BigInteger generatePrivateKey ( ) throws NoSuchAlgorithmException {
        Random randomGenerator = SecureRandom.getInstance ( "SHA1PRNG" );
        return new BigInteger ( NUM_BITS , randomGenerator );
    }

    /**
     * Calculates the public key.
     *
     * @param privateKey the private key
     *
     * @return the public key
     */
    public static BigInteger calculatePublicKey ( BigInteger privateKey ) {
        return G.modPow ( privateKey , N );
    }

    /**
     * Computes the secret key.
     *
     * @param publicKey  the public key
     * @param privateKey the private key
     *
     * @return the secret key
     */
    public static BigInteger computeSecret ( BigInteger publicKey , BigInteger privateKey ) {
        return publicKey.modPow ( privateKey , N );
    }

}
