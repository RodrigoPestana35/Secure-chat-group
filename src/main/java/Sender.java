import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class represents the sender of the message. It sends the message to the receiver by means of a socket. The use
 * of Object streams enables the sender to send any kind of object.
 */
public class Sender implements Runnable {

    private static final String HOST = "0.0.0.0";
    private int port = 8000;
    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final PublicKey publicRSAKey;
    private final PrivateKey privateRSAKey;
    private String username;
    private HashMap <String, PublicKey> usersPublicKey = new HashMap<>();
    private HashMap <String, byte[]> sharedSecrets = new HashMap<>();
    private byte[] userSharedSecret;
    private MessageFrame messageFrame;

    public String getUsername() {
        return username;
    }

    /**
     * Constructs a Sender object by specifying the port to connect to. The socket must be created before the sender can
     * send a message.
     *
     * @throws Exception when an I/O error occurs when creating the socket
     */
    public Sender ( ) throws Exception {
        client = new Socket ( HOST , port );
        System.out.println("Connected to the server! at port " + port);
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        in = new ObjectInputStream ( client.getInputStream ( ) );

        Scanner scanner = new Scanner(System.in);
        System.out.println("Por favor, insira o seu nome:");
        boolean validName = false;
        while (!validName) {
            String name = scanner.nextLine();
            if (name.length() > 0) {
                this.username = name;
                validName = true;
            } else {
                System.out.println("Nome em uso. Por favor, insira um nome válido:");
            }
        }
//        String name = scanner.nextLine();
//        this.username = name;
        System.out.println("Username: "+username);
        out.writeObject(username);

        messageFrame = new MessageFrame(this);
        messageFrame.setVisible(true);

        KeyPair keyPair = Encryption.generateKeyPair();
        this.publicRSAKey = keyPair.getPublic();
        this.privateRSAKey = keyPair.getPrivate();

        Certificate certificate = createCertificate();
        String certificateBase64 = encodeCertificateToBase64(certificate);
        createPemFile(certificateBase64, username);
        out.writeObject();

        //Receiver.usersPublicKey.put(username, publicRSAKey);
        //Message inOuts = new Message(username.getBytes(), "2".getBytes());
        //out.writeObject(inOuts);
        //tirar depois
        //Message publicRSAKeyForEveryone = new Message(publicRSAKey.getEncoded(),username.getBytes(), "3".getBytes());
        //out.writeObject(publicRSAKeyForEveryone);
    }

//    private PublicKey rsaKeyDistributionSend() throws IOException, ClassNotFoundException {
//        out.writeObject(this.publicRSAKey);
//        return (PublicKey) in.readObject();
//    }
//
//    private PublicKey rsaKeyDistributionReceive() throws IOException, ClassNotFoundException {
//        PublicKey publicKey = (PublicKey) in.readObject();
//        out.writeObject(this.publicRSAKey);
//        return publicKey;
//    }

    /**
     * Sends a message to the receiver using the OutputStream of the socket. The message is sent as an object of the
     * {@link Message} class.
     *
     * @param message the message to send
     *
     * @throws Exception when an I/O error occurs when sending the message
     */
    public void sendMessage ( String message, String receiver ) throws Exception {
        System.out.println("Sending message to: " + receiver);
        PublicKey receiverPublicRSAKey = usersPublicKey.get(receiver); //isto não existe
        if(!sharedSecrets.containsKey(receiver)){
            userSharedSecret = agreeOnSharedSecretSend(receiverPublicRSAKey, receiver).toByteArray();
            sharedSecrets.put(receiver, userSharedSecret);
        }
        else{
            userSharedSecret = sharedSecrets.get(receiver);
        }

        // Creates the message object
        byte[] messageEncrypted = Encryption.encryptAES ( message.getBytes ( ), userSharedSecret );
        byte[] digest = Encryption.encryptRSA(Integrity.generateDigest(message.getBytes()),receiverPublicRSAKey);
        String control = "0";
        Message messageObj = new Message ( messageEncrypted, digest, username.getBytes(), receiver.getBytes());
        //Message messageObj = new Message ( message.getBytes(), receiver.getBytes(), username.getBytes());
        // Sends the message
        out.writeObject ( messageObj );
        // Close connection
        //closeConnection ( );
    }

    public void receiveMessage (Message messageObj) throws Exception {
        //CORRIGIRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR
//        PublicKey senderPublicRSAKey = usersPublicKey.get(new String(messageObj.getSender()));
//
//        byte[] sharedSecret = agreeOnSharedSecretReceive(senderPublicRSAKey).toByteArray();
//
//        byte[] decryptedMessage = Encryption.decryptAES( messageObj.getMessage ( ), sharedSecret );
//        byte[] computedDigest = Integrity.generateDigest(decryptedMessage);
//        byte[] receivedDigest = Encryption.decryptRSA(messageObj.getDigest(), privateRSAKey);
//        if(Integrity.verifyDigest(computedDigest, receivedDigest)){
//            System.out.println(new String(decryptedMessage));
//        }
        String message = new String(messageObj.getMessage(), StandardCharsets.UTF_8);
        String receiver = new String(messageObj.getReceiver(), StandardCharsets.UTF_8);
        System.out.println(receiver+": "+message);
    }

    private BigInteger agreeOnSharedSecretReceive(PublicKey senderPublicRSAKey) throws Exception {
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);

        Message messageSenderPublicKeyEncrypted = (Message) (in.readObject());
        byte[] senderPublicKeyDecrypted = Encryption.decryptRSA(messageSenderPublicKeyEncrypted.getMessage(), senderPublicRSAKey);

        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(),privateRSAKey);
        Secret messagePublicEncrypted = new Secret(publicKeyEncrypted, messageSenderPublicKeyEncrypted.getSender(), username.getBytes());
        sendPublicKey(messagePublicEncrypted);

        return DiffieHellman.computeSecret(new BigInteger(senderPublicKeyDecrypted), privateDHKey);
    }

    private BigInteger agreeOnSharedSecretSend(PublicKey receiverPublicRSAKey, String receiver) throws Exception {
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);

        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(), privateRSAKey);
        Secret messagePublicEncrypted = new Secret(publicKeyEncrypted, receiver.getBytes() , username.getBytes());
        sendPublicKey(messagePublicEncrypted);

        Message messageReceiverPublicKeyEncrypted = (Message) (in.readObject());
        byte[] receiverPublicKeyDecrypted = Encryption.decryptRSA(messageReceiverPublicKeyEncrypted.getMessage(), receiverPublicRSAKey);

        return DiffieHellman.computeSecret(new BigInteger(receiverPublicKeyDecrypted),privateDHKey);
    }

    private void sendPublicKey(Secret publicKeyEncrypted) throws IOException {
        out.writeObject(publicKeyEncrypted);
    }

    private Certificate createCertificate() throws Exception {
        Certificate certificate = new Certificate(username, publicRSAKey);
        return certificate;
    }

    private String encodeCertificateToBase64(Certificate certificate) {
        try {
            // Convertendo o objeto Certificate para byte[]
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(certificate);
            oos.close();
            byte[] certificateBytes = baos.toByteArray();

            // Codificando o byte[] para Base64
            String certificateBase64 = Base64.getEncoder().encodeToString(certificateBytes);

            return certificateBase64;
        } catch (IOException e) {
            throw new RuntimeException("Erro ao codificar o certificado para Base64", e);
        }
    }

    private void createPemFile(String certificateBase64, String username) {
        try {
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

            // Define o nome do ficheiro
            String timestamp = String.valueOf(Instant.now().getEpochSecond());
            String fileName = username + ".pem";

            // Cria o ficheiro .pem
            File pemFile = new File(directoryName + "/" + fileName);
            pemFile.createNewFile();

            // Escreve no ficheiro .pem
            FileWriter writer = new FileWriter(pemFile);
            writer.write("-----BEGIN CERTIFICATE-----\n");
            writer.write(certificateBase64 + "\n");
            writer.write("-----END CERTIFICATE-----\n");
            writer.close();
        } catch (IOException e) {
            throw new RuntimeException("Erro ao criar o ficheiro .pem", e);
        }
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
                    System.out.println("Escreva para enviar a mensagem:");
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
                        message = message.replaceFirst(matcher.group(), "");
                    }
                    //retira espaços em branco do inicio e do fim
                    message = message.trim();
                    // Converte a lista em um array
                    String[] receivers = parts.toArray(new String[0]);
                    System.out.println("Receivers:");
                    if (receivers.length == 0) {
                        sendMessage(message, "all");
                    }
                    else {
                        for (int i = 0; i < receivers.length; i++) {
                            System.out.println(receivers[i]);
                            sendMessage(message, receivers[i]);
                        }
                    }
                    //sendMessage(message, "all");
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
                    Object obj = in.readObject();
                    System.out.println("Message received");
                    if(obj instanceof Message){
                        Message message = (Message) obj;
//                        if (Arrays.equals(message.getControl(), "3".getBytes())) {
//                            byte[] userPublicKeyBytes = message.getMessage();
//                            X509EncodedKeySpec spec = new X509EncodedKeySpec(userPublicKeyBytes);
//                            KeyFactory kf = KeyFactory.getInstance("RSA");
//                            PublicKey userPublicKey = kf.generatePublic(spec);
//                            usersPublicKey.put(new String(message.getSender()), userPublicKey);
//                        }
//                        else if (Arrays.equals(message.getControl(), "0".getBytes())) {
//                            receiveMessage(message);
//                        }
//                        else{
//                            receiveMessage(message);
//                        }
                        receiveMessage(message);
                    }
                    else if(obj instanceof Secret){
                        Secret secret = (Secret) obj;
                        String receiver = new String(secret.getReceiver(), StandardCharsets.UTF_8);
                        if(!sharedSecrets.containsKey(receiver)){
                            userSharedSecret = agreeOnSharedSecretReceive();
                            sharedSecrets.put(receiver, userSharedSecret);
                        }
                        else{
                            userSharedSecret = sharedSecrets.get(receiver);
                        }
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
            receiverThread.start();
            senderThread.start();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
