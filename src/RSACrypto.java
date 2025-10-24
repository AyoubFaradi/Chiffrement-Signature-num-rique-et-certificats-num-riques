import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class RSACrypto {
    private static final String KEYSTORE_PATH = "certs/devoir.jks";
    private static final String CERT_PATH = "certs/certificate.cert";
    private static final String STOREPASS = "123456";
    private static final String KEYPASS = "123456";
    private static final String ALIAS = "devoir";

    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;

    private static PublicKey loadPublicKeyFromCert() throws Exception {
        try (FileInputStream fis = new FileInputStream(CERT_PATH)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(fis);
            return cert.getPublicKey();
        }
    }

    private static PrivateKey loadPrivateKeyFromJKS() throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            ks.load(fis, STOREPASS.toCharArray());
        }
        return (PrivateKey) ks.getKey(ALIAS, KEYPASS.toCharArray());
    }

    private static SecretKey genAesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg.generateKey();
    }

    public static String hybridEncryptBase64(String plain) throws Exception {
        SecretKey aesKey = genAesKey();
        byte[] iv = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = aes.doFinal(plain.getBytes());

        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, loadPublicKeyFromCert());
        byte[] encAesKey = rsa.doFinal(aesKey.getEncoded());

        ByteBuffer bb = ByteBuffer.allocate(2 + encAesKey.length + iv.length + ct.length);
        bb.putShort((short) encAesKey.length);
        bb.put(encAesKey);
        bb.put(iv);
        bb.put(ct);

        return Base64.getEncoder().encodeToString(bb.array());
    }

    public static String hybridDecryptBase64(String base64) throws Exception {
        byte[] all = Base64.getDecoder().decode(base64);
        ByteBuffer bb = ByteBuffer.wrap(all);

        int keyLen = bb.getShort() & 0xFFFF;
        byte[] encAesKey = new byte[keyLen];
        bb.get(encAesKey);

        byte[] iv = new byte[GCM_IV_BYTES];
        bb.get(iv);

        byte[] ct = new byte[bb.remaining()];
        bb.get(ct);

        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.DECRYPT_MODE, loadPrivateKeyFromJKS());
        byte[] aesKeyBytes = rsa.doFinal(encAesKey);

        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plain = aes.doFinal(ct);
        return new String(plain);
    }

    public static void demo() throws Exception {
        String message = "Bonjour a tout le monde";
        String enc = hybridEncryptBase64(message);
        System.out.println("[RSACrypto] Hybrid (Base64): " + enc);
        String dec = hybridDecryptBase64(enc);
        System.out.println("[RSACrypto] Decrypted: " + dec);
    }
}
