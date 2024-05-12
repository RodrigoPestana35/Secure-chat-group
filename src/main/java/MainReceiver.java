import java.io.File;

/**
 * Class that starts the server and the CA
 */
public class MainReceiver {

    /**
     * Main method
     * @param args arguments
     * @throws Exception if an error occurs
     */
    public static void main ( String[] args ) throws Exception {
        // Define o nome do diretório
        String directoryName = "certificates";

        // Cria o diretório, se não existir
        File directory = new File(directoryName);
        if (!directory.exists()) {
            directory.mkdir();
        } else {
            // Se o diretório já existir, apaga todos os ficheiros existentes
            for (File file : directory.listFiles()) {
                file.delete();
            }
        }
        Receiver receiver = new Receiver ( 8000 );
        CA ca = new CA ( );
        Thread caThread = new Thread ( ca );
        Thread serverThread = new Thread ( receiver );
        serverThread.start ( );
        caThread.start ( );
    }

}
