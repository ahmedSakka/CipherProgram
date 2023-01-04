import java.util.Scanner;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.util.Arrays;

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
      
      public static byte[] padMessage(byte[] message) {
        int numPadBytes = 8 - message.length % 8;
        byte[] paddedMessage = Arrays.copyOf(message, message.length + numPadBytes);
        for (int i = message.length; i < paddedMessage.length; i++) {
          paddedMessage[i] = 0;
        }
        return paddedMessage;
      }
      
      // Removes the padding from the given message
      public static byte[] removePadding(byte[] message) {
        int numPadBytes = 0;
        for (int i = message.length - 1; i > 0; i--) {
          if (message[i] == 0) {
            numPadBytes++;
          } else {
            break;
          }
        }
        return Arrays.copyOf(message, message.length - numPadBytes);
      }
      
      public static String decrypt(byte[] encryptedMessage, SecretKey key, byte[] iv) throws Exception {
        // Initialize cipher in decrypt mode
        Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
      
        // Pad the encrypted message
        encryptedMessage = padMessage(encryptedMessage);
      
        // Decrypt message
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
      
        // Remove padding
        decryptedMessage = removePadding(decryptedMessage);
      
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
      