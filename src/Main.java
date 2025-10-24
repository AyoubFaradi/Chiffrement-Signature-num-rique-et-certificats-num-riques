public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("Partie 2: AESCrypto (RSA public/private)");
        AESCrypto.demo();

        System.out.println("\nPartie 3: RSACrypto (RSA + AES Hybrid)");
        RSACrypto.demo();

        System.out.println("\nPartie 4 & 5: HMAC Signature & Vérification");
        String doc = "Bonjour tout le monde";
        String sig = HmacSign.sign(doc);
        System.out.println("Signature HMAC (Base64): " + sig);
        boolean ok = HmacVerify.verify(doc, sig);
        System.out.println("Vérification: " + (ok ? "INTÈGRE" : "ALTÉRÉ"));
    }
}
