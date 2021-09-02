import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;
import java.util.stream.Stream;

public class EncryptorCLI {
    /* Collection of ANSI escape codes which format a String when printed to console */
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";

    /* Renders array as a String using an indent of 4 spaces */
    public static String toFormattedString(BigInteger[] a) {
        return Arrays.toString(a)
            .replace("[", "[\n" + " ".repeat(4))
            .replace(",", ",\n" + " ".repeat(3))
            .replace("]", "\n]");
    }

    /* Saves a set of RSA keys to a local file */
    public static BigInteger[][] save(BigInteger[][] a) throws IOException {
        String[] toSave = Stream.of(a).map(EncryptorCLI::toFormattedString).toArray(String[]::new);
        String data = "/* DO NOT EDIT THIS FILE! DELETE FILE TO GENERATE A NEW SET OF KEYS. */\n\n/* PUBLIC KEY STARTS */\n"
            + toSave[0] + "\n/* PUBLIC KEY ENDS */\n\n/* PRIVATE KEY STARTS */\n"
            + toSave[1] + "\n/* PRIVATE KEY ENDS */\n";

        FileWriter w = new FileWriter(new File("keys.txt"));
        w.write(data);
        w.close();

        return a;
    }

    public static void main(String[] args) throws IOException {
        Scanner scan = new Scanner(System.in);
        System.out.println(ANSI_GREEN + "** WELCOME TO ENCRYPTOR CLI **" + ANSI_RESET);
        System.out.print(ANSI_YELLOW + "\nEnter value to be encrypted or decrypted here: ");

        String text = scan.nextLine();
        System.out.print(ANSI_RESET);

        boolean isInteger = text.matches("\\d+");
        BigInteger parsed = isInteger ? new BigInteger(text) : BigInteger.ZERO;
        boolean encrypted = parsed.bitLength() == 2048 || parsed.bitLength() + 8 - parsed.bitLength() % 8 == 2048;

        scan.close();

        File saved = new File("keys.txt");
        BigInteger[][] keys;

        if (saved.exists()) {
            BufferedReader r = new BufferedReader(new FileReader(new File("keys.txt")));
            String data = String.join("", r.lines().toArray(String[]::new));

            keys = Stream.of(data.replaceAll("[^\\d,\\]]", "").split("]"))
                .map(s -> Stream.of(s.split(",")).map(n -> new BigInteger(n)).toArray(BigInteger[]::new))
                .toArray(BigInteger[][]::new);

            r.close();
        } else if (encrypted) {
            System.out.println(
                ANSI_RED + "✖ No keys found. Make sure that `keys.txt` shares the same directory as EncryptorCLI."
                + ANSI_RESET);

            return;
        } else {
            keys = save(Encryptor.generateKeys());

            System.out.println(
                ANSI_YELLOW + "⚠️  EncryptorCLI could not locate any existing keys, so new ones were generated"
                + ANSI_RESET);
        };

        Encryptor e = encrypted ? new Encryptor(new BigInteger(text), keys) : new Encryptor(text, keys);
        String result = encrypted ? e.toDecryptedString() : e.toEncryptedInteger().toString();

        System.out.println(result == null ?
            ANSI_RED + "✖ The encrypted integer passed is incompatible with the saved keys." + ANSI_RESET :
            ANSI_GREEN + "✔ Success! The text has been " + (encrypted ? "decrypted: " : "encrypted: ") + result + ANSI_RESET);
    }
}
