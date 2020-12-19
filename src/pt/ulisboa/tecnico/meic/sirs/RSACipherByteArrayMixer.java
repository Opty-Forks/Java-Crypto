package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Implementation of the RSA cipher as a ByteArrayMixer
 */
public class RSACipherByteArrayMixer implements ByteArrayMixer {

    private String keyFile;
    private String mode;
    private int opmode;
    private final int PAYLOAD = 117;
    private final int BLOCK = 128;

    public void setParameters(String keyFile, String mode) {
        this.keyFile = keyFile;
        this.mode = mode;
    }

    public RSACipherByteArrayMixer(int opmode) {
        this.opmode = opmode;
    }

    @Override
    public byte[] mix(byte[] byteArray, byte[] byteArray2) {

        try {
            Key key = opmode == Cipher.ENCRYPT_MODE ? RSAKeyGenerator.readPub(keyFile) : RSAKeyGenerator.readPriv(keyFile);

            // get a DES cipher object and print the provider
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA/" + mode + "/PKCS1Padding", "BC");
            System.out.println(cipher.getProvider().getInfo());

            System.out.println("Ciphering ...");
            if (!mode.equals("ECB")) {
                // look! A null IV!
                cipher.init(this.opmode, key, new IvParameterSpec(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
            } else {
                cipher.init(this.opmode, key);
            }

            ByteBuffer buf = ByteBuffer.allocate((byteArray.length / PAYLOAD + 1) * BLOCK);

            for (int idx = 0; idx < byteArray.length; idx += opmode == Cipher.ENCRYPT_MODE ? PAYLOAD : BLOCK) {

                int len = opmode == Cipher.ENCRYPT_MODE ? Math.min(byteArray.length - idx, PAYLOAD) : BLOCK;
                byte[] enc = cipher.doFinal(byteArray, idx, len);
                buf.put(enc);
            }

            return buf.array();

        } catch (Exception e) {
            // Pokemon exception handling!
            e.printStackTrace();
        }
        return null;
    }
}
