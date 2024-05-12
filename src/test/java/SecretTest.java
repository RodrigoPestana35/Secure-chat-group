import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecretTest {

    Secret secret;

    @BeforeEach
    void setUp() {
        byte[] _secret = "secret".getBytes();
        byte[] _receiver = "receiver".getBytes();
        byte[] _sender = "sender".getBytes();
        secret = new Secret(_secret, _receiver, _sender);
    }

    @Test
    void getSecret() {
        assertArrayEquals(secret.getSecret(), "secret".getBytes());
    }

    @Test
    void getReceiver() {
        assertArrayEquals(secret.getReceiver(), "receiver".getBytes());
    }

    @Test
    void getSender() {
        assertArrayEquals(secret.getSender(), "sender".getBytes());
    }
}