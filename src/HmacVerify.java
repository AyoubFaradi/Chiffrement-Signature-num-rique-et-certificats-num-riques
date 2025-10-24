import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;

public class HmacVerify {
    private static final byte[] HMAC_KEY = "SuperSecretHmacKeyForDemo".getBytes();

    public static boolean verify(String message, String base64Signature) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(HMAC_KEY, "HmacSHA256"));
        byte[] expected = mac.doFinal(message.getBytes());
        byte[] provided = Base64.getDecoder().decode(base64Signature);
        return MessageDigest.isEqual(expected, provided);
    }
}
