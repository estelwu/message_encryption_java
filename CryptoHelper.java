import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptoHelper {

  private static final String CLIENT_PUBLIC_KEY_FILENAME = "public.key";
  private static final String CLIENT_PRIVATE_KEY_FILENAME = "private.key";
  private static final String SERVER_PUBLIC_KEY_FILENAME = "public.key";

  private PrivateKey mRSAPrivateKey;
  private PublicKey mRSAPublicKey;
  private SecretKey mAesKey;

  public static void main(String[] args) throws Exception {
    CryptoHelper helper = new CryptoHelper();
    String msg = "Hello World";
    System.out.println(msg);
    String enMsg = helper.msgEncrypt(msg);
    System.out.println(enMsg);

    String enKey = helper.aesKeyEncrypt();
    String deMsg = helper.msgDecrypt(enMsg, enKey);
    System.out.println(deMsg);
  }

  public CryptoHelper() throws Exception {
    // Initialize RSA Key.
    KeyFactory kf = KeyFactory.getInstance("RSA");
    // Read Client RSA Private Key to decrypt data received from server.
    byte[] encodedPrivateKey = readKeyFile(CLIENT_PRIVATE_KEY_FILENAME);
    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
    this.mRSAPrivateKey = kf.generatePrivate(privateKeySpec);

    // Read Server RSA Public Key to encrypt data send to server.
    byte[] encodedPublicKey = readKeyFile(SERVER_PUBLIC_KEY_FILENAME);
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
    this.mRSAPublicKey = kf.generatePublic(publicKeySpec);

    // Initialize AES Key.
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(128);
    this.mAesKey = generator.generateKey();
  }

  private byte[] readKeyFile(String filename) throws IOException {
    File initialFile = new File(filename);
    InputStream stream = new FileInputStream(initialFile);
    byte[] fileBytes = new byte[stream.available()];
    stream.read(fileBytes); // Read stream into fileBytes.
    stream.close();
    return fileBytes;
  }

  public String aesKeyEncrypt() throws Exception {
    // Encrypt AES key with RSA public key.
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(Cipher.PUBLIC_KEY, this.mRSAPublicKey);
    byte[] enAesKey = cipher.doFinal(this.mAesKey.getEncoded());
    return Base64.getEncoder().encodeToString(enAesKey);
  }

  public String msgEncrypt(String message) throws Exception {
    Cipher aesCipher = Cipher.getInstance("AES");
    aesCipher.init(Cipher.ENCRYPT_MODE, this.mAesKey);
    byte[] enMsg = aesCipher.doFinal(message.getBytes());
    return Base64.getEncoder().encodeToString(enMsg);
  }

  public byte[] aesKeyDecrypt(String enAesKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(Cipher.PRIVATE_KEY, this.mRSAPrivateKey);
    return cipher.doFinal(Base64.getDecoder().decode(enAesKey));
  }

  public String msgDecrypt(String encryptedMsg, String encryptedKey) throws Exception {
    // Decrypt AES key with RSA private key.
    byte[] deAesKey = aesKeyDecrypt(encryptedKey);
    SecretKey aesKey = new SecretKeySpec(deAesKey, 0, deAesKey.length, "AES");
    // Use AES key to decrypt message.
    Cipher aesCipher = Cipher.getInstance("AES");
    aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
    byte[] decryptedMsg = aesCipher.doFinal(Base64.getDecoder().decode(encryptedMsg));
    return new String(decryptedMsg);
  }

}