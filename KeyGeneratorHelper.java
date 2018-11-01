import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;

public class KeyGeneratorHelper {
  public static void main(String[] args) throws Exception {
    // generate public and private keys
    KeyPair keyPair = buildKeyPair();
    PublicKey pubKey = keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();
    System.out.println("Public key : " + pubKey);
    System.out.println("Public key encoded : " + Arrays.toString((pubKey.getEncoded())));
    System.out.println("Public key format : " + pubKey.getFormat());
    System.out.println("Private key : " + privateKey);

    EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKey.getEncoded());
    // KeyFactory is used to convert keys into key specs.
    // A key might have multiple compatible key specifications,
    // eg: A DSA public key may be DSAPublicKeySpec or X509EncodeKeySpec.
    // the compatible key spec can be translated.
    KeyFactory kf = KeyFactory.getInstance("RSA");
    PublicKey regeneratedPublicKey = kf.generatePublic(keySpec);

    // encrypt the message
    byte[] encrypted = encrypt(regeneratedPublicKey, "This is a secret message");
    System.out.println(new String(encrypted)); // <<encrypted message>>

    // decrypt the message
    byte[] secret = decrypt(privateKey, encrypted);
    System.out.println(new String(secret)); // This is a secret message

    writeBytesToFile(privateKey.getEncoded(), "private.key");
    writeBytesToFile(pubKey.getEncoded(), "public.key");
  }

  public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
    final int keySize = 2048;
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(keySize);
    return keyPairGenerator.genKeyPair();
  }

  public static byte[] encrypt(PublicKey pubKey, String message) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, pubKey);

    return cipher.doFinal(message.getBytes());
  }

  public static byte[] decrypt(PrivateKey privateKey, byte[] encrypted) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);

    return cipher.doFinal(encrypted);
  }

  private static void writeBytesToFile(byte[] bytes, String filename) {
    File file = new File(filename);
    try {
      FileOutputStream fos = new FileOutputStream(file);
      fos.write(bytes);
      fos.close();
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}
