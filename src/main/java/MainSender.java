import java.util.Scanner;

public class MainSender {

    public static void main ( String[] args ) throws Exception {
        Sender sender = new Sender ( );
        Thread clientThread = new Thread ( sender );
        clientThread.start ( );
    }

}
