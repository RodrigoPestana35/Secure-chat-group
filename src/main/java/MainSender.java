import java.util.Scanner;

/**
 * Class that starts the client
 */
public class MainSender {

    /**
     * Main method
     * @param args arguments
     * @throws Exception if an error occurs
     */
    public static void main ( String[] args ) throws Exception {
        Sender sender = new Sender ( );
        Thread clientThread = new Thread ( sender );
        clientThread.start ( );
    }

}
