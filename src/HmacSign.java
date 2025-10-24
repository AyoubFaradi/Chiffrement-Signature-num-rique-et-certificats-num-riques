import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class HmacSign {
    private static final byte[] HMAC_KEY = "SuperSecretHmacKeyForDemo".getBytes();

    public static String sign(String message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(HMAC_KEY, "HmacSHA256"));
        byte[] sig = mac.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(sig);
    }
}
