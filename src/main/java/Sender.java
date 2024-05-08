import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.Thread.sleep;

/**
 * This class represents the sender of the message. It sends the message to the receiver by means of a socket. The use
 * of Object streams enables the sender to send any kind of object.
 */
public class Sender implements Runnable {

    private static final String HOST = "0.0.0.0";
    private int port = 8000;
    private final Socket client;
    private final Socket clientCA;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final ObjectInputStream inCA;
    private final ObjectOutputStream outCA;
    private final PublicKey publicRSAKey;
    private final PrivateKey privateRSAKey;
    private String username;
    private CertificateEnvelope myCertificateEnvelope;
    private HashMap <String, PublicKey> usersPublicKey = new HashMap<>();
    private HashMap <String, byte[]> sharedSecrets = new HashMap<>();
    private byte[] userSharedSecret;
    private MessageFrame messageFrame;
    private Secret2 messageReceiverPublicKeyEncrypted;
    private List<String> clients = new ArrayList<>();

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
        out = new ObjectOutputStream ( client.getOutputStream ( ) );
        in = new ObjectInputStream ( client.getInputStream ( ) );
        System.out.println("Connected to the server! at port " + port);

        clientCA = new Socket ( HOST , 8080 );
        outCA = new ObjectOutputStream ( clientCA.getOutputStream ( ) );
        inCA = new ObjectInputStream ( clientCA.getInputStream ( ) );

        Scanner scanner = new Scanner(System.in);
        System.out.println("Por favor, insira o seu nome:");
        boolean validName = false;
        while (!validName) {
            String name = scanner.nextLine();
            if (doesFileExist(name) || name.equals("")){
                System.out.println("Nome em uso. Por favor, insira outro nome:");
            } else {
                this.username = name;
                validName = true;
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
        System.out.println("Public RSA Key: " + publicRSAKey);

//        Certificate certificate = createCertificate();
//        String certificateBase64 = encodeCertificateToBase64(certificate);
//        createPemFile(certificateBase64, username);
//        String path = "certificates/" + username + ".pem";
//        System.out.println("Path: " + path);
//        outCA.writeObject(path);
//        System.out.println("Certificate sent to CA");
//        CertificateEnvelope certificateEnvelope = (CertificateEnvelope) inCA.readObject();
//        System.out.println("Certificate received from CA");
//        out.writeObject(certificateEnvelope);
//        System.out.println("Certificate sent to server");

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

    private void certification() throws Exception {
        Certificate certificate = createCertificate();
        String certificateBase64 = encodeCertificateToBase64(certificate);
        createPemFile(certificateBase64, username);
        String path = "certificates/" + username + ".pem";
        System.out.println("Path: " + path);
        outCA.writeObject(path);
        System.out.println("Certificate sent to CA");
        myCertificateEnvelope = (CertificateEnvelope) inCA.readObject();
        System.out.println("Certificate received from CA");
        out.writeObject(myCertificateEnvelope);
        System.out.println("Certificate sent to server");

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
        System.out.println("Sending message to: " + receiver);
        PublicKey receiverPublicRSAKey = usersPublicKey.get(receiver);
        System.out.println("tem chave public");
        if(!sharedSecrets.containsKey(receiver)){
            System.out.println("nao tem shared secret");
            userSharedSecret = agreeOnSharedSecretSend(receiverPublicRSAKey, receiver).toByteArray();
            sharedSecrets.put(receiver, userSharedSecret);
            System.out.println("shared secret no hashmap");
        }
        else{
            System.out.println("tem shared secret");
            userSharedSecret = sharedSecrets.get(receiver);
        }

        // Creates the message object
        byte[] messageEncrypted = Encryption.encryptAES ( message.getBytes ( ), userSharedSecret );
        byte[] digest = Encryption.encryptRSA(Integrity.generateDigest(message.getBytes()),receiverPublicRSAKey);
        Message messageObj = new Message ( messageEncrypted, digest, username.getBytes(), receiver.getBytes());
        System.out.println("Message created");
        //Message messageObj = new Message ( message.getBytes(), receiver.getBytes(), username.getBytes());
        // Sends the message
        out.writeObject ( messageObj );
        System.out.println("Message sent");
        // Close connection
        //closeConnection ( );


    }

    public void receiveMessage (Message messageObj) throws Exception {
        //TODO: CORRIGIRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR
        if (sharedSecrets.containsKey(new String(messageObj.getSender(), StandardCharsets.UTF_8))){
            userSharedSecret = sharedSecrets.get(new String(messageObj.getSender(), StandardCharsets.UTF_8));
        }
        else{
            PublicKey senderPublicRSAKey = usersPublicKey.get(new String(messageObj.getSender(), StandardCharsets.UTF_8));
            userSharedSecret = agreeOnSharedSecretReceive(senderPublicRSAKey).toByteArray();
            sharedSecrets.put(new String(messageObj.getSender(), StandardCharsets.UTF_8), userSharedSecret);
        }
//        PublicKey senderPublicRSAKey = usersPublicKey.get(new String(messageObj.getSender(), StandardCharsets.UTF_8));
//
//        byte[] sharedSecret = agreeOnSharedSecretReceive(senderPublicRSAKey).toByteArray();

        byte[] decryptedMessage = Encryption.decryptAES( messageObj.getMessage ( ), userSharedSecret );
        byte[] computedDigest = Integrity.generateDigest(decryptedMessage);
        byte[] receivedDigest = Encryption.decryptRSA(messageObj.getDigest(), privateRSAKey);
        if(Integrity.verifyDigest(computedDigest, receivedDigest)){
            System.out.println(new String(decryptedMessage));
            messageFrame.displayMessage(new String(decryptedMessage));
        }
        String message = new String(messageObj.getMessage(), StandardCharsets.UTF_8);
        String receiver = new String(messageObj.getReceiver(), StandardCharsets.UTF_8);
        System.out.println(receiver+": "+message);
    }

    private BigInteger agreeOnSharedSecretReceive(PublicKey senderPublicRSAKey) throws Exception {
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);
        System.out.println("chaves diffie hellman geradas");

        Secret messageSenderPublicKeyEncrypted = (Secret) (in.readObject());
        System.out.println("recebeu public key");
        byte[] senderPublicKeyDecrypted = Encryption.decryptRSA(messageSenderPublicKeyEncrypted.getSecret(), senderPublicRSAKey);

        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(),privateRSAKey);
        Secret messagePublicEncrypted = new Secret(publicKeyEncrypted, messageSenderPublicKeyEncrypted.getSender(), username.getBytes());
        System.out.println("secret criada");
        out.writeObject(messagePublicEncrypted);
        System.out.println("public key enviada");

        return DiffieHellman.computeSecret(new BigInteger(senderPublicKeyDecrypted), privateDHKey);
    }

    private BigInteger agreeOnSharedSecretSend(PublicKey receiverPublicRSAKey, String receiver) throws Exception {
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);
        System.out.println("chaves diffie hellman geradas");

        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(), privateRSAKey);
        Secret messagePublicEncrypted = new Secret(publicKeyEncrypted, receiver.getBytes() , username.getBytes());
        System.out.println("secret criada");
        out.writeObject(messagePublicEncrypted);
        System.out.println("public key enviada");

        //Secret2 messageReceiverPublicKeyEncrypted = (Secret2) (in.readObject());
        while(messageReceiverPublicKeyEncrypted==null){
            sleep(10);
        }
        System.out.println("recebeu public key");
        System.out.println("sender: " + new String(messageReceiverPublicKeyEncrypted.getSender(), StandardCharsets.UTF_8));
        byte[] receiverPublicKeyDecrypted = Encryption.decryptRSA(messageReceiverPublicKeyEncrypted.getSecret(), receiverPublicRSAKey);

        sharedSecrets.put(receiver, DiffieHellman.computeSecret(new BigInteger(receiverPublicKeyDecrypted),privateDHKey).toByteArray());

        messageReceiverPublicKeyEncrypted= null;

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

            return Base64.getEncoder().encodeToString(certificateBytes);
        } catch (IOException e) {
            throw new RuntimeException("Erro ao codificar o certificado para Base64", e);
        }
    }

    private void createPemFile(String certificateBase64, String username) {
        try {
            // Define o nome do ficheiro
            String timestamp = String.valueOf(Instant.now().getEpochSecond());
            String fileName = username + ".pem";

            // Cria o ficheiro .pem
            File pemFile = new File("certificates/" + fileName);
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

    public boolean doesFileExist(String name) {
        File directory = new File("certificates");
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    String fileName = file.getName();
                    if (fileName.endsWith(".pem")) {
                        String nameWithoutExtension = fileName.substring(0, fileName.length() - 4);
                        if (nameWithoutExtension.equals(name)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public PublicKey getPublicKeyFromEncodedBytes(byte[] publicKeyBytes) {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao converter bytes para PublicKey", e);
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
                        for (String receiver : clients) {
                            if (!receiver.equals(username)) {
                                sendMessage(message, receiver);
                            }
                        }
                        //sendMessage(message, "all");
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
                    System.out.println("Object received");

                    if(obj instanceof Message){
                        Message message = (Message) obj;
                        System.out.println("objeto messagem");
                        receiveMessage(message);
                    }
                    else if(obj instanceof Secret){
                        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
                        BigInteger publicDHKey = DiffieHellman.calculatePublicKey(privateDHKey);
                        System.out.println("recebeu secret");
                        Secret secret = (Secret) obj;
                        System.out.println("recebeu public key");
                        System.out.println("sender: " + new String(secret.getSender(), StandardCharsets.UTF_8));
                        PublicKey senderPublicRSAKey = usersPublicKey.get(new String(secret.getSender(), StandardCharsets.UTF_8));
                        System.out.println("tem chave public " + senderPublicRSAKey);
                        byte[] senderPublicKeyDecrypted = Encryption.decryptRSA(secret.getSecret(), senderPublicRSAKey);

                        byte[] publicKeyEncrypted = Encryption.encryptRSA(publicDHKey.toByteArray(),privateRSAKey);
                        Secret2 messagePublicEncrypted = new Secret2(publicKeyEncrypted, secret.getSender(), username.getBytes());
                        System.out.println("secret criada");
                        //sleep(5000);
                        out.writeObject(messagePublicEncrypted);
                        System.out.println("public key enviada");
                        sharedSecrets.put(new String(secret.getSender(), StandardCharsets.UTF_8), DiffieHellman.computeSecret(new BigInteger(senderPublicKeyDecrypted), privateDHKey).toByteArray());
                        System.out.println("shared secret no hashmap" + sharedSecrets.get(new String(secret.getSender(), StandardCharsets.UTF_8)));
                    }
                    else if( obj instanceof Secret2){
                        System.out.println("recebeu secret");
                        messageReceiverPublicKeyEncrypted = (Secret2) obj;
                        System.out.println("recebeu public key");
                    }
                    else if(obj instanceof CertificateEnvelope){
                        System.out.println("recebeu certificado");
                        CertificateEnvelope certificateEnvelope = (CertificateEnvelope) obj;
                        System.out.println("get Certificate: " + certificateEnvelope.getCertificate());
                        // Converte o array de bytes de volta para um objeto Certificate
                        byte[] certificateBytes = Base64.getDecoder().decode(certificateEnvelope.getCertificate().replaceAll("\n", ""));
                        ByteArrayInputStream byteStream = new ByteArrayInputStream(certificateBytes);
                        ObjectInputStream objStream = new ObjectInputStream(byteStream);
                        Certificate certificate = (Certificate) objStream.readObject();
                        System.out.println("1 Certificate username: " + certificate.getUsername());
                        if (!usersPublicKey.containsKey(certificate.getUsername()) && !certificate.getUsername().equals(username)){
                            byte[] newDigest = Integrity.generateDigest(certificateEnvelope.getCertificate().getBytes());
                            PublicKey CApublicRSAKey = getPublicKeyFromEncodedBytes(certificateEnvelope.getPublicKey());
                            byte[] signature = Encryption.decryptRSA(certificateEnvelope.getSignature(), CApublicRSAKey);
                            if(Integrity.verifyDigest(newDigest, signature)){
                                System.out.println("Certificado válido");
                                clients.add(certificate.getUsername());
                                //coloca nome e chave publica no hashmap
                                System.out.println("2 Certificate username: " + certificate.getUsername());
                                System.out.println("2 Certificate public key: " + certificate.getPublicRSAKey());
                                usersPublicKey.put(certificate.getUsername(), certificate.getPublicRSAKey());
                                //sleep(15000);
                                //envia o seu certificado para todos tambem, quem ja tiver ignora quem nao tiver guarda
                                out.writeObject(myCertificateEnvelope);
                                LocalDateTime now = LocalDateTime.now();
                                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm");
                                String formatDateTime = now.format(formatter);
                                System.out.println(formatDateTime + ": O utilizador " + certificate.getUsername() + " ligou-se ao Chat.");
                            }
                        }
                        else if (usersPublicKey.containsKey(certificate.getUsername()) && !certificate.getUsername().equals(username)){
                            System.out.println("O utilizador " + certificate.getUsername() + " já se encontra ligado ao Chat.");
                        }




//                        byte[] newDigest = Integrity.generateDigest(certificateEnvelope.getCertificate().getBytes());
//                        PublicKey CApublicRSAKey = getPublicKeyFromEncodedBytes(certificateEnvelope.getPublicKey());
//                        byte[] signature = Encryption.decryptRSA(certificateEnvelope.getSignature(), CApublicRSAKey);
//                        if(Integrity.verifyDigest(newDigest, signature)){
//                            System.out.println("Certificado válido");
//                            // Decodifica a string Base64 para um array de bytes
////                            System.out.println("get Certificate: " + certificateEnvelope.getCertificate());
////                            byte[] certificateBytes = Base64.getDecoder().decode(certificateEnvelope.getCertificate().replaceAll("\n", ""));
////                            // Converte o array de bytes de volta para um objeto Certificate
////                            ByteArrayInputStream byteStream = new ByteArrayInputStream(certificateBytes);
////                            ObjectInputStream objStream = new ObjectInputStream(byteStream);
////                            Certificate certificate = (Certificate) objStream.readObject();
//                            //coloca nome e chave publica no hashmap
//                            System.out.println("Certificate username: " + certificate.getUsername());
//                            System.out.println("Certificate public key: " + certificate.getPublicRSAKey());
//                            if (!usersPublicKey.containsKey(certificate.getUsername()) && !certificate.getUsername().equals(username)){
//                                usersPublicKey.put(certificate.getUsername(), certificate.getPublicRSAKey());
//                                out.writeObject(myCertificate);
//                                LocalDateTime now = LocalDateTime.now();
//                                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm");
//                                String formatDateTime = now.format(formatter);
//                                System.out.println(formatDateTime + ": O utilizador " + certificate.getUsername() + " ligou-se ao Chat.");
//                            }
//                            else {
//                                LocalDateTime now = LocalDateTime.now();
//                                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm");
//                                String formatDateTime = now.format(formatter);
//                                System.out.println(formatDateTime + ": O utilizador " + certificate.getUsername() + " ligou-se ao Chat.");
//                                System.out.println("O utilizador " + certificate.getUsername() + " já se encontra ligado ao Chat.");
//                            }

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
            //certificado
            certification();
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
