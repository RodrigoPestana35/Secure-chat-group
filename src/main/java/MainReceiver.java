public class MainReceiver {

    public static void main ( String[] args ) throws Exception {
        Receiver receiver = new Receiver ( 8000 );
        Thread serverThread = new Thread ( receiver );
        serverThread.start ( );
    }

}
