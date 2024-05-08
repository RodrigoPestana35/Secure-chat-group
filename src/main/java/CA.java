import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.concurrent.locks.ReentrantLock;

public class CA implements Runnable {
    private final ServerSocket server;
    private ObjectOutputStream outCA;
    private ObjectInputStream inCA;
    private PublicKey publicRSAKey;
    private PrivateKey privateRSAKey;
    private static final ReentrantLock lock = new ReentrantLock();

    public CA() throws Exception {
        server = new ServerSocket(8080);
        KeyPair keyPair =  KeyPairGenerator.getInstance("RSA").generateKeyPair();
        this.publicRSAKey = keyPair.getPublic();
        this.privateRSAKey = keyPair.getPrivate();
    }



    public void signCertificate(Certificate certificate) throws Exception {
        //logica para ir buscar o certificado

        //logica para assinar o certificado
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateRSAKey);
        privateSignature.update(certificate.getUsername().getBytes());
        byte[] signature = privateSignature.sign();
        certificate.setSignature(signature);

    }

    public String getCertificateContent(String filePath) {
        StringBuilder certificateContent = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            boolean isCertificateContent = false;
            while ((line = reader.readLine()) != null) {
                if (line.equals("-----BEGIN CERTIFICATE-----")) {
                    isCertificateContent = true;
                    continue;
                }
                if (line.equals("-----END CERTIFICATE-----")) {
                    isCertificateContent = false;
                }
                if (isCertificateContent) {
                    certificateContent.append(line).append("\n");
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Erro ao ler o ficheiro", e);
        }
        return certificateContent.toString();
    }

    @Override
    public void run() {
        try {
            while (true) {
                lock.lock();
                Socket client = server.accept();
                outCA = new ObjectOutputStream(client.getOutputStream());
                inCA = new ObjectInputStream(client.getInputStream());
                System.out.println("Client connected: " + client.getInetAddress());

                //cria uma nova thread para tratar do pedido
                new Thread(() -> {
                    System.out.println("Thread started");
                    try {
                        String path = (String) inCA.readObject();
                        System.out.println("Path: " + path);
                        String certificateContent = getCertificateContent(path);
                        byte[] digest = Integrity.generateDigest(certificateContent.getBytes());
                        byte[] digestEncrypted = Encryption.encryptRSA(digest, privateRSAKey);
                        CertificateEnvelope certificateEnvelope = new CertificateEnvelope(certificateContent, digestEncrypted, publicRSAKey.getEncoded());
                        System.out.println("Certificate envelope created and send");
                        outCA.writeObject(certificateEnvelope);
                        System.out.println("Certificate envelope sent");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
                lock.unlock();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
