import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.stream.Stream;

public class Encryptor {
    /* Fifth prime integer in Fermat's sequence */
    public static final BigInteger F4 = BigInteger.valueOf(65537);

    /* An integer which can be decoded to plaintext */
    private BigInteger data;

    /* Set of RSA keys where the first element is the public key & the second is the private key */
    private BigInteger[][] keys;

    /* Initializes Encryptor with plaintext */
    public Encryptor(String text, BigInteger[][] keys) {
        this.data = Encryptor.toInteger(text);
        this.keys = keys;
    }

    /* Initializes Encryptor with an encoded integer */
    public Encryptor(BigInteger data, BigInteger[][] keys) {
        this.data = data;
        this.keys = keys;
    }

    /* Generates two pairs of RSA keys */
    public static BigInteger[][] generateKeys() {
        BigInteger[] factors = new BigInteger[2];
        BigInteger product = BigInteger.ZERO;
        BigInteger base = BigInteger.ZERO;
        
        boolean selectedFactor = false;
        while (!selectedFactor) {
            factors[0] = BigInteger.probablePrime(1024, new SecureRandom());
            factors[1] = BigInteger.probablePrime(1024, new SecureRandom());

            product = factors[0].multiply(factors[1]);

            factors[0] = factors[0].subtract(BigInteger.ONE);
            factors[1] = factors[1].subtract(BigInteger.ONE);

            base = factors[0].multiply(factors[1]);

            selectedFactor = !base.mod(F4).equals(BigInteger.ZERO) && product.bitLength() == 2048;
        }

        BigInteger secretExponent = F4.modInverse(base);

        return new BigInteger[][]{
            new BigInteger[]{ F4, product },
            new BigInteger[]{ secretExponent, product },
        };
    }

    /* Encodes plaintext to an integer */
    public static BigInteger toInteger(String text) {
        String[] bLetters = text.codePoints().boxed()
            .map(b -> "0".repeat(8 - Integer.toString(b, 2).length()) + Integer.toString(b, 2))
            .toArray(String[]::new);
        
        String bString = String.join("", bLetters);
        
        return new BigInteger(bString, 2);
    }

    /* Decodes an integer to plaintext */
    public static String toString(BigInteger text) {
        String bString = text.toString(2);
        bString = "0".repeat(8 - bString.length() % 8) + bString;
        
        Integer[] bLetters = Stream.of(bString.split("(?<=\\G.{8})"))
            .map(b -> Integer.parseInt(b, 2))
            .toArray(Integer[]::new);
        String[] letters = Stream.of(bLetters).map(Character::toString).toArray(String[]::new);
        
        boolean safe = !Stream.of(bLetters).anyMatch(b -> b > 127);
        
        return safe ? String.join("", letters) : new String();
    }

    /* Decrypts an encrypted integer to plaintext using a private RSA key set */
    public String toDecryptedString() {
        BigInteger secretExponent = this.keys[1][0];
        BigInteger base = this.keys[1][1];

        return Encryptor.toString(this.data.modPow(secretExponent, base));
    }

    /* Encrypts an integer whose value can be decoded to plaintext using public RSA key set */
    public BigInteger toEncryptedInteger() {
        BigInteger publicExponent = this.keys[0][0];
        BigInteger base = this.keys[0][1];

        return this.data.modPow(publicExponent, base);
    }
}
