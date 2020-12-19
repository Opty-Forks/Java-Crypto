package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Cipher;
import java.io.IOException;

/**
 * Encrypts an image with the RSA algorithm in multiple modes, with a given, appropriate RSA private key
 */
public class ImageRSADecipher {

    public static void main(String[] args) throws IOException {

        if (args.length != 4) {
            System.err.println("This program encrypts an image file with RSA.");
            System.err.println("Usage: ImageRSADecipher [inputFile.png] [RSAKeyFile] [ECB|CBC|OFB] [outputFile.png]");
            return;
        }

        final String inputFile = args[0];
        final String keyFile = args[1];
        final String mode = args[2].toUpperCase();
        final String outputFile = args[3];

        if (!(mode.equals("ECB") || mode.equals("CBC") || mode.equals("OFB"))) {
            System.err.println("The modes of operation must be ECB, CBC or OFB.");
            return;
        }

        RSACipherByteArrayMixer cipher = new RSACipherByteArrayMixer(Cipher.DECRYPT_MODE);
        cipher.setParameters(keyFile, mode);
        ImageMixer.mix(inputFile, outputFile, cipher);
    }
}
