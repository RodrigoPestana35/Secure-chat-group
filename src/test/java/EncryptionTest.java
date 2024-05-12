import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class EncryptionTest {
    public Encryption encryption;
    public Encryption encryption2;
    @BeforeEach
    void setUp() throws Exception {
        this.encryption = new Encryption();
        this.encryption2 = new Encryption();
    }
    @Test
    void testGenerateKeyPair() throws NoSuchAlgorithmException {
        assertNotEquals(encryption.generateKeyPair(),encryption2.generateKeyPair());
    }
    @Test
    void testEncryptRSA() throws Exception {
        byte[] test = "test".getBytes();
        Key key = encryption.generateKeyPair().getPublic();
        assertNotEquals(encryption.encryptRSA(test,key),encryption2.encryptRSA(test,key));
    }
}
