public class MainCA {
    public static void main ( String[] args ) throws Exception {
        CA ca = new CA ( );
        Thread caThread = new Thread ( ca );
        caThread.start ( );
    }
}
