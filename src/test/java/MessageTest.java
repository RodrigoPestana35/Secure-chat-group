import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MessageTest {

    private static Message message;
    static String receiver;
    static String sender;
    @BeforeAll
    static void setUp() throws Exception {
        receiver = "Receiver";
        sender = "Sender";
        byte[] msg = "test".getBytes();
        byte [] digest = Integrity.generateDigest(msg);
        message = new Message(msg, digest, sender.getBytes(), receiver.getBytes());
    }

    @Test
    void getMessage() {
        byte[] test = "test".getBytes();
        byte[] msg = message.getMessage();
        assertArrayEquals(test, msg);
    }

    @Test
    void getDigest() throws Exception {
        assertArrayEquals(message.getDigest(), Integrity.generateDigest("test".getBytes()));
    }

    @Test
    void getReceiver() {
        assertArrayEquals(message.getReceiver(), "Receiver".getBytes());
    }

    @Test
    void getSender() {
        assertArrayEquals(message.getSender(), "Sender".getBytes());
    }
}