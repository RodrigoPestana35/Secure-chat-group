import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class represents the sender of the message. It sends the message to the receiver by means of a socket. The use
 * of Object streams enables the sender to send any kind of object.
 */
public class Sender implements Runnable {

    private static final String HOST = "0.0.0.0";
    private static int port = 8000;
    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final PublicKey publicRSAKey;
    private final PrivateKey privateRSAKey;
    private PublicKey receiverPublicRSAKey;
    private String username;
    private static int ID = 1;

    /**
     * Constructs a Sender object by specifying the port to connect to. The socket must be created before the sender can
     * send a message.
     *
     * @throws Exception when an I/O error occurs when creating the socket
     */
    public Sender ( ) throws Exception {
        client = new Socket ( HOST , port );
        port++;
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        in = new ObjectInputStream ( client.getInputStream ( ) );

        this.username="User"+ID;
        ID++;

        KeyPair keyPair = Encryption.generateKeyPair();
        this.publicRSAKey = keyPair.getPublic();
        this.privateRSAKey = keyPair.getPrivate();
    }

    private PublicKey rsaKeyDistributionSend() throws IOException, ClassNotFoundException {
        out.writeObject(this.publicRSAKey);
        return (PublicKey) in.readObject();
    }

    private PublicKey rsaKeyDistributionReceive() throws IOException, ClassNotFoundException {
        PublicKey publicKey = (PublicKey) in.readObject();
        out.writeObject(this.publicRSAKey);
        return publicKey;
    }

    /**
     * Sends a message to the receiver using the OutputStream of the socket. The message is sent as an object of the
     * {@link Message} class.
     *
     * @param message the message to send
     *
     * @throws Exception when an I/O error occurs when sending the message
     */
    public void sendMessage ( String message, String receiver ) throws Exception {
        receiverPublicRSAKey = rsaKeyDistributionSend();
        byte[] sharedSecret = agreeOnSharedSecretSend(receiverPublicRSAKey).toByteArray();
        // Creates the message object
        byte[] messageEncrypted = Encryption.encryptAES ( message.getBytes ( ), sharedSecret );
        byte[] digest = Encryption.encryptRSA(Integrity.generateDigest(message.getBytes()),privateRSAKey);
        Message messageObj = new Message ( messageEncrypted, digest, username, receiver );
        // Sends the message
        out.writeObject ( messageObj );
        // Close connection
        closeConnection ( );
    }

    public void receiveMessage (Message messageObj) throws Exception {
        PublicKey senderPublicRSAKey = rsaKeyDistributionReceive();

        byte[] sharedSecret = agreeOnSharedSecretReceive(senderPublicRSAKey).toByteArray();

        byte[] decryptedMessage = Encryption.decryptAES( messageObj.getMessage ( ), sharedSecret );
        byte[] computedDigest = Integrity.generateDigest(decryptedMessage);
        byte[] receivedDigest = Encryption.decryptRSA(messageObj.getDigest(), senderPublicRSAKey);
        if(Integrity.verifyDigest(computedDigest, receivedDigest)){
            System.out.println(new String(decryptedMessage));
        }
    }

    private BigInteger agreeOnSharedSecretReceive(PublicKey senderPublicRSAKey) throws Exception {
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);

        byte[] senderPublicKeyEncrypted = (byte[]) (in.readObject());
        byte[] senderPublicKeyDecrypted = Encryption.decryptRSA(senderPublicKeyEncrypted, senderPublicRSAKey);

        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(),privateRSAKey);
        sendPublicKey(publicKeyEncrypted);

        return DiffieHellman.computeSecret(new BigInteger(senderPublicKeyDecrypted), privateDHKey);
    }

    private BigInteger agreeOnSharedSecretSend(PublicKey receiverPublicRSAKey) throws Exception {
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);

        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(), privateRSAKey);
        sendPublicKey(publicKeyEncrypted);

        byte[] receiverPublicKeyEncrypted = (byte[])(in.readObject());
        byte[] receiverPublicKeyDecrypted = Encryption.decryptRSA(receiverPublicKeyEncrypted, receiverPublicRSAKey);

        return DiffieHellman.computeSecret(new BigInteger(receiverPublicKeyDecrypted),privateDHKey);
    }

    private void sendPublicKey(byte[] publicKeyEncrypted) throws IOException {
        out.writeObject(publicKeyEncrypted);
    }

    /**
     * Closes the connection by closing the socket and the streams.
     *
     * @throws IOException when an I/O error occurs when closing the connection
     */
    private void closeConnection ( ) throws IOException {
        client.close ( );
        out.close ( );
        in.close ( );
    }

    private class MessageSender implements Runnable {
        @Override
        public void run() {
            try {
                while (true){
                    Scanner scanner = new Scanner(System.in);
                    System.out.println("Por favor, insira algo:");
                    String message = scanner.nextLine();
                    // Cria um padrão para encontrar partes que começam com "@"
                    Pattern pattern = Pattern.compile("@\\w+");
                    Matcher matcher = pattern.matcher(message);
                    // Cria uma lista para armazenar as partes encontradas
                    List<String> parts = new ArrayList<>();
                    // Encontra todas as partes que correspondem ao padrão
                    while (matcher.find()) {
                        // Adiciona a parte encontrada à lista, removendo o "@"
                        parts.add(matcher.group().substring(1));
                    }
                    // Converte a lista em um array
                    String[] receivers = parts.toArray(new String[0]);
                    if (receivers.length == 0) {
                        sendMessage(message, "all");
                    }
                    else {
                        for (int i = 0; i < receivers.length; i++) {
                            sendMessage(message, receivers[i]);
                        }
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    private class MessageReceiver implements Runnable {
        @Override
        public void run() {
            try {
                while (true){
                    Message message = (Message) in.readObject();
                    if(message instanceof Message){
                        receiveMessage(message);
                    }

                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public void run() {
        try {
            //conexao com o servidor e certificado

            //inicialização das threads responsaveis por enviar e receber mensagens
            Thread senderThread = new Thread(new MessageSender());
            Thread receiverThread = new Thread(new MessageReceiver());
            senderThread.start();
            receiverThread.start();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
