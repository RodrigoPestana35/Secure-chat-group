import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class MessageFrame extends JFrame {
    private JTextArea messageArea;
    private JTextField inputField;
    private JButton sendButton;
    private Sender sender;

    public MessageFrame(Sender sender) {
        this.sender = sender;

        setTitle("Sender: " + sender.getUsername());
        setSize(500, 500);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        messageArea = new JTextArea();
        messageArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(messageArea);
        add(scrollPane, BorderLayout.CENTER);

        JPanel panel = new JPanel();
        inputField = new JTextField(30);
        sendButton = new JButton("Enviar");
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String message = inputField.getText();
                // Aqui você pode implementar a lógica para enviar a mensagem
                // sender.sendMessage(message);
                inputField.setText("");
            }
        });

        panel.add(inputField);
        panel.add(sendButton);
        add(panel, BorderLayout.SOUTH);
    }

    public void displayMessage(String message) {
        messageArea.append(message + "\n");
    }
}