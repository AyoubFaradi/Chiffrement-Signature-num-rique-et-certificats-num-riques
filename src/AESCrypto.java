import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class AESCrypto {
    private static final String KEYSTORE_PATH = "certs/devoir.jks";
    private static final String CERT_PATH = "certs/certificate.cert";
    private static final String STOREPASS = "123456";
    private static final String KEYPASS = "123456";
    private static final String ALIAS = "devoir";

    public static java.security.PublicKey loadPublicKeyFromCert() throws Exception {
        try (FileInputStream fis = new FileInputStream(CERT_PATH)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(fis);
            return cert.getPublicKey();
        }
    }

    public static PrivateKey loadPrivateKeyFromJKS() throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            ks.load(fis, STOREPASS.toCharArray());
        }
        return (PrivateKey) ks.getKey(ALIAS, KEYPASS.toCharArray());
    }

    public static String rsaEncryptBase64(String plain) throws Exception {
        var pub = loadPublicKeyFromCert();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] cipherBytes = cipher.doFinal(plain.getBytes());
        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    public static String rsaDecryptBase64(String base64Cipher) throws Exception {
        var priv = loadPrivateKeyFromJKS();
        byte[] cipherBytes = Base64.getDecoder().decode(base64Cipher);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, priv);
        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return new String(plainBytes);
    }

    public static void demo() throws Exception {
        String message = "Bonjour tout le monde";
        String encrypted = rsaEncryptBase64(message);
        System.out.println("[AESCrypto] Encrypted (Base64): " + encrypted);
        String decrypted = rsaDecryptBase64(encrypted);
        System.out.println("[AESCrypto] Decrypted: " + decrypted);
    }

}
