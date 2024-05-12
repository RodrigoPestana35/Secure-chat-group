import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class MessageFrameTest {


    private MessageFrame messageFrame;
    StyledDocument doc;
    @BeforeEach
    void setUp() throws Exception {
        //sender = new Sender();
        //receiver = new Receiver ( 8000 );
        messageFrame = new MessageFrame("client");
        doc = new JTextPane().getStyledDocument();
    }

    @Test
    void displayMessage() throws Exception {
        messageFrame.displayMessage("Test", "sender", true);

        SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm");
        Date date = new Date();
        String dateFormatted = dateFormat.format(date);

        doc.insertString(doc.getLength(), "sender: Test" + " (" + dateFormatted + ")" + "\n", null);

        String p = doc.getParagraphElement(0).toString();
        String p1 = messageFrame.doc.getParagraphElement(0).toString();
        assertEquals(p, p1) ;
    }
}