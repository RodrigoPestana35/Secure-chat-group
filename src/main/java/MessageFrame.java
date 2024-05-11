import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.Console;
import java.text.SimpleDateFormat;
import java.util.Date;

public class MessageFrame extends JFrame {
    private JTextPane messageArea;
    private JTextField inputField;
    private JButton sendButton;
    private String sender;
    public String message;
    StyledDocument doc;

    public MessageFrame(String sender) {

        this.sender = sender;
        setTitle("Sender: " + sender);
        setSize(500, 500);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        messageArea = new JTextPane();
        messageArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(messageArea);
        add(scrollPane, BorderLayout.CENTER);

        JPanel panel = new JPanel();
        inputField = new JTextField(30);
        sendButton = new JButton("Enviar");
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                message = inputField.getText();
                System.out.println("MENSAGEM ENVIADA: " + message);
                // Aqui você pode implementar a lógica para enviar a mensagem
                // sender.sendMessage(message);
                inputField.setText("");
            }
        });

        panel.add(inputField);
        panel.add(sendButton);
        add(panel, BorderLayout.SOUTH);

        doc = messageArea.getStyledDocument();

    }


    public void displayMessage(String message, String sender, boolean isMessage) throws BadLocationException {
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm");
        Date date = new Date();
        String dateFormatted = dateFormat.format(date);
        Style redStyle = doc.addStyle("Red", null);
        StyleConstants.setForeground(redStyle, Color.RED);
        StyleConstants.setFontSize(redStyle, 15);

        Style messageStyle = doc.addStyle("User", null);
        StyleConstants.setFontSize(messageStyle, 15);

        Style userStyle = doc.addStyle("User", null);
        StyleConstants.setBold(userStyle, true);
        StyleConstants.setFontSize(userStyle, 15);

        if (!isMessage) {

            doc.insertString(doc.getLength(), message + sender, redStyle);
            StyleConstants.setFontSize(redStyle, 10);
            doc.insertString(doc.getLength()," (" + dateFormatted + ")" + "\n", redStyle);
        }
        else {
            doc.insertString(doc.getLength(), sender + ": ", userStyle);
            doc.insertString(doc.getLength(), message, messageStyle);
            StyleConstants.setFontSize(messageStyle, 10);
            doc.insertString(doc.getLength(),  " (" + dateFormatted + ")" + "\n", messageStyle);
        }
    }
}