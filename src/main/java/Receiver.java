import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.*;

/**
 * This class represents a server that receives a message from the client. The server is implemented as a thread.
 */
public class Receiver implements Runnable {

    private final ServerSocket server;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private Socket client;
    private HashMap<String, ObjectInputStream> usersIns;
    private HashMap<String, ObjectOutputStream> usersOuts;
    private HashMap<ObjectInputStream, ObjectOutputStream> insOuts;

    /**
     * Constructs a Receiver object by specifying the port number.
     *
     * @param port the port number
     *
     * @throws Exception if an I/O error occurs when creating the server socket
     */
    public Receiver ( int port ) throws Exception {
        server = new ServerSocket ( port );
        this.usersIns = new HashMap<>();
        this.usersOuts = new HashMap<>();
        this.insOuts = new HashMap<>();
    }

    /**
     * Runs the server.
     */
    @Override
    public void run() {
        try {
            while (true) {
                Socket client = server.accept();
                ObjectInputStream in = new ObjectInputStream(client.getInputStream());
                ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream());
                String username = ( String ) in.readObject();
                System.out.println("username: " + username);
                usersIns.put(username, in);
                usersOuts.put(username, out);
                insOuts.put(in, out);
                System.out.println("Client " + username +  " connected: " + client.getInetAddress());
                new Thread(() -> {
                    try {
                        while (true) {
                            System.out.println("try do run");
                            process(in);
                        }
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }).start();
            }
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Processes the message received from the client and forwards to receivers.
     *
     * @param in the input stream
     *
     * @throws Exception if an I/O error occurs when reading the object
     */
    private void process ( ObjectInputStream in ) throws Exception {
        System.out.println("entra process");
        Object obj = in.readObject();
        if(obj instanceof Message){
            System.out.println("le objeto");
            Message messageObj = ( Message ) obj;
            System.out.println("depois de adquirir message");
            //System.out.println(Arrays.equals(messageObj.getControl(), "0".getBytes()));
            if ( Arrays.equals(messageObj.getReceiver(), "all".getBytes())){
                System.out.println("entrou ALL");
                for (ObjectOutputStream out : usersOuts.values()) {
                    try {
                        System.out.println("envia mensagem");
                        out.writeObject(messageObj);
                    } catch (IOException e) {
                        System.err.println("Erro ao enviar objeto: " + e.getMessage());
                    }
                }
            }
            else{
                System.out.println("entrou ELSE");
                String receiverName = new String(messageObj.getReceiver(), StandardCharsets.UTF_8);
                ObjectOutputStream receiverOut = usersOuts.get(receiverName);
                receiverOut.writeObject(messageObj);
            }
        }
        else if (obj instanceof CertificateEnvelope){
            CertificateEnvelope certificateEnvelope = (CertificateEnvelope) obj;
            if(!usersOuts.isEmpty()){
                for (ObjectOutputStream out : usersOuts.values()) {
                    try {
                        if(!out.equals(insOuts.get(in))){
                            System.out.println("envia certificateEnvelope1");
                            out.writeObject(certificateEnvelope);
                        }
                    } catch (IOException e) {
                        System.err.println("Erro ao enviar objeto: " + e.getMessage());
                    }
                }
            }
            else {
                System.out.println("Não tem mais ninguem no chat");

                for (ObjectOutputStream out : usersOuts.values()) {
                    try {
                        System.out.println("envia certificateEnvelope2");
                        out.writeObject(certificateEnvelope);
                    } catch (IOException e) {
                        System.err.println("Erro ao enviar objeto: " + e.getMessage());
                    }
                }
            }

        }
        else if (obj instanceof Secret){
            System.out.println("entrou secret");
            Secret secret = (Secret) obj;
            String receiver = new String(secret.getReceiver(), StandardCharsets.UTF_8);
            System.out.println("receiver: " + receiver);
            if (receiver.equals("all")){
                for (ObjectOutputStream out : usersOuts.values()) {
                    try {
                        System.out.println("envia secret all");
                        out.writeObject(secret);
                        System.out.println("secret enviado all");
                    } catch (IOException e) {
                        System.err.println("Erro ao enviar objeto: " + e.getMessage());
                    }
                }
            }
            else {
                ObjectOutputStream receiverOut = usersOuts.get(receiver);
                if (receiverOut != null) {
                    System.out.println("envia secret");
                    receiverOut.writeObject(secret);
                    System.out.println("secret enviado");
                } else {
                    System.err.println("Erro: ObjectOutputStream para " + receiver + " é nulo");
                }
            }

        }
        else if (obj instanceof Secret2){
            System.out.println("entrou secret");
            Secret2 secret = (Secret2) obj;
            String receiver = new String(secret.getReceiver(), StandardCharsets.UTF_8);
            System.out.println("receiver: " + receiver);
            if (receiver.equals("all")){
                for (ObjectOutputStream out : usersOuts.values()) {
                    try {
                        System.out.println("envia secret all");
                        out.writeObject(secret);
                        System.out.println("secret enviado all");
                    } catch (IOException e) {
                        System.err.println("Erro ao enviar objeto: " + e.getMessage());
                    }
                }
            }
            else {
                ObjectOutputStream receiverOut = usersOuts.get(receiver);
                if (receiverOut != null) {
                    System.out.println("envia secret");
                    receiverOut.writeObject(secret);
                    System.out.println("secret enviado");
                } else {
                    System.err.println("Erro: ObjectOutputStream para " + receiver + " é nulo");
                }
            }

        }
        else if (obj instanceof Certificate){
            Certificate certificate = (Certificate) obj;
            if(!usersOuts.isEmpty()) {
                for (ObjectOutputStream out : usersOuts.values()) {
                    try {
                        if (!out.equals(insOuts.get(in))) {
                            System.out.println("envia certificate1");
                            out.writeObject(certificate);
                        }
                    } catch (IOException e) {
                        System.err.println("Erro ao enviar objeto: " + e.getMessage());
                    }
                }
            }
        }
    }

    /**
     * Closes the connection and the associated streams.
     *
     * @throws IOException if an I/O error occurs when closing the socket
     */
    private void closeConnection ( ) throws IOException {
        client.close ( );
        out.close ( );
        in.close ( );
    }

}