import java.io.File;

public class MainReceiver {

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
        Thread serverThread = new Thread ( receiver );
        serverThread.start ( );
    }

}
