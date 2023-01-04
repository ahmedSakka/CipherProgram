import java.util.Scanner;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class DESCipher {
    public static byte[] encrypt(String message, SecretKey key, byte[] iv) throws Exception {
        // Initialize cipher in encrypt mode
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
      
        // Encrypt message
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
      
        return encryptedMessage;
      }
      
      
      public static String decrypt(byte[] encryptedMessage, SecretKey key, byte[] iv) throws Exception {
        // Initialize cipher in decrypt mode
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
      
        // Decrypt message
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
      
        return new String(decryptedMessage);
      }
      

public static void main(String[] args) throws Exception {
Scanner sc = new Scanner(System.in);

// Generate secret key
KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
SecretKey secretKey = keyGenerator.generateKey();

// Generate initialization vector (IV)
SecureRandom secureRandom = new SecureRandom();
byte[] iv = new byte[8];
secureRandom.nextBytes(iv);

// Prompt user to choose between encryption and decryption
System.out.println("Enter 1 to encrypt or 2 to decrypt:");
int operationChoice = sc.nextInt();

if (operationChoice == 1) {

  // Encrypt message
  System.out.println("Enter the message to encrypt:");
  String message = sc.next();
  byte[] encryptedMessage = DESCipher.encrypt(message, secretKey, iv);
  System.out.println("Encrypted message: " + Base64.getEncoder().encodeToString(encryptedMessage));
  System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));

} else if (operationChoice == 2) {

  // Decrypt message
  System.out.println("Enter the message to decrypt:");
  String encryptedMessageString = sc.next();
  byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageString);
  System.out.println("Enter the IV:");
  String ivString = sc.next();
  iv = Base64.getDecoder().decode(ivString);
  String decryptedMessage = DESCipher.decrypt(encryptedMessage, secretKey, iv);
  System.out.println("Decrypted message: " + decryptedMessage);
}

}
}
