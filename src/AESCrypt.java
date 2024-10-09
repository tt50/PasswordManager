import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Scanner;

// Used source code from https://gist.github.com/MartynClark/125c0e3bc436ac259a1e9a3d20f5d854
public class AESCrypt {

    private static final String ALGORITHM = "AES";
    private static final String KEY = "1Hbfh667adfDEJ78"; // 16 bytes for AES-128

    public static String encrypt(String value) throws Exception {
        Key key = generateKey();
        Cipher cipher = Cipher.getInstance(AESCrypt.ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedByteValue = cipher.doFinal(value.getBytes("utf-8"));
        return Base64.getEncoder().encodeToString(encryptedByteValue);
    }

    public static String decrypt(String value) throws Exception {
        Key key = generateKey();
        Cipher cipher = Cipher.getInstance(AESCrypt.ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedValue64 = Base64.getDecoder().decode(value);
        byte[] decryptedByteValue = cipher.doFinal(decryptedValue64);
        return new String(decryptedByteValue, "utf-8");
    }

    private static Key generateKey() {
        return new SecretKeySpec(KEY.getBytes(), ALGORITHM);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the password to encrypt: ");
        String password = scanner.nextLine();

        String encryptedPassword;
        try {
            encryptedPassword = AESCrypt.encrypt(password);
            System.out.println("Encrypted: " + encryptedPassword);
            String decryptedPassword = AESCrypt.decrypt(encryptedPassword);
            System.out.println("Decrypted: " + decryptedPassword);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
    }