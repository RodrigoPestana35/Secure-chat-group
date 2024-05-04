import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

/**
 * This class represents a server that receives a message from the client. The server is implemented as a thread.
 */
public class Receiver implements Runnable {

    private final ServerSocket server;
    private final PublicKey publicRSAKey;
    private final PrivateKey privateRSAKey;
    private ObjectInputStream in;
    private ObjectOutputStream out;
    private Socket client;
    public static List<String> users = new ArrayList<>();
    private HashMap<String, ObjectInputStream> usersIns;
    private HashMap<String, ObjectOutputStream> usersOuts;

    /**
     * Constructs a Receiver object by specifying the port number. The server will be then created on the specified
     * port. The Receiver will be accepting connections from all local addresses.
     *
     * @param port the port number
     *
     * @throws IOException if an I/O error occurs when opening the socket
     */
    public Receiver ( int port ) throws Exception {
        server = new ServerSocket ( port );
        KeyPair keyPair = Encryption.generateKeyPair();
        this.publicRSAKey = keyPair.getPublic();
        this.privateRSAKey = keyPair.getPrivate();
        this.usersIns = new HashMap<>();
        this.usersOuts = new HashMap<>();
    }

    @Override
    public void run() {
        try {
            while (true) {
                Socket client = server.accept();
                ObjectInputStream in = new ObjectInputStream(client.getInputStream());
                ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream());
                System.out.println("Client connected: " + client.getInetAddress());
                new Thread(() -> {
                    try {
                        System.out.println("try do run");
                        process(in);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }).start();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Processes the request from the client.
     *
     * @param in the input stream
     *
     * @throws Exception if an I/O error occurs when reading the message
     */
    private void process ( ObjectInputStream in ) throws Exception {
        System.out.println("entra process");
        Object obj = in.readObject();
        if(obj instanceof Message){
            System.out.println("le objeto");
            Message messageObj = ( Message ) obj;
            System.out.println("depois de adquirir message");
            if (Arrays.equals(messageObj.getControl(), "0".getBytes())){
                System.out.println("control 0");
                System.out.println ( "Message received: " + new String ( messageObj.getMessage ( ) ) );
                String receiverName = messageObj.getReceiver().toString();

                ObjectOutputStream receiverOut = usersOuts.get(receiverName);
                receiverOut.writeObject(messageObj);
                System.out.println("enviou mensagem");
            }
            else if (Arrays.equals(messageObj.getControl(), "1".getBytes())){
                System.out.println("control 1");
                System.out.println ( "Message received: " + new String ( messageObj.getMessage ( ) ) );
                String receiverName = messageObj.getReceiver().toString();
                ObjectOutputStream receiverOut = usersOuts.get(receiverName);
                receiverOut.writeObject(messageObj);
                System.out.println("saiu control 1");
            }
            else if (Arrays.equals(messageObj.getControl(), "2".getBytes())){
                System.out.println("control 2");
                if(!usersIns.containsKey(messageObj.getMessage().toString()) && !usersOuts.containsKey(messageObj.getMessage().toString())){
                    usersIns.put(messageObj.getMessage().toString(), this.in);
                    usersOuts.put(messageObj.getMessage().toString(), this.out);
                }
                else {
                    System.out.println("Usuário já existe");
                }
                System.out.println("saiu control 2");
            }
            else if (Arrays.equals(messageObj.getControl(), "3".getBytes())){
                System.out.println("control 3");
                for (ObjectOutputStream out : usersOuts.values()) {
                    try {
                        out.writeObject(messageObj);
                    } catch (IOException e) {
                        System.err.println("Erro ao enviar objeto: " + e.getMessage());
                    }
                }
            }
        }
    }

//    private BigInteger agreeOnSharedSecret(PublicKey senderPublicRSAKey) throws Exception {
//        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
//        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);
//
//        byte[] senderPublicKeyEncrypted = (byte[]) (in.readObject());
//        byte[] senderPublicKeyDecrypted = Encryption.decryptRSA(senderPublicKeyEncrypted, senderPublicRSAKey);
//
//        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(),privateRSAKey);
//        sendPublicKey(publicKeyEncrypted);
//
//        return DiffieHellman.computeSecret(new BigInteger(senderPublicKeyDecrypted), privateDHKey);
//    }
//
//    private PublicKey rsaKeyDistribution() throws IOException, ClassNotFoundException {
//        PublicKey publicKey = (PublicKey) in.readObject();
//        out.writeObject(this.publicRSAKey);
//        return publicKey;
//    }

    private void sendPublicKey(byte[] publicKeyEncrypted) throws IOException {
        out.writeObject(publicKeyEncrypted);
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