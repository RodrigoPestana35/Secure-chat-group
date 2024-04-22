import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class DiffieHellman {


    private static final int NUM_BITS = 128;
    private static final BigInteger N = new BigInteger ( "1289971646" );
    private static final BigInteger G = new BigInteger ( "3" );

    public static BigInteger generatePrivateKey ( ) throws NoSuchAlgorithmException {
        Random randomGenerator = SecureRandom.getInstance ( "SHA1PRNG" );
        return new BigInteger ( NUM_BITS , randomGenerator );
    }

    public static BigInteger calculatePublicKey ( BigInteger privateKey ) {
        return G.modPow ( privateKey , N );
    }

    public static BigInteger computeSecret ( BigInteger publicKey , BigInteger privateKey ) {
        return publicKey.modPow ( privateKey , N );
    }

}
