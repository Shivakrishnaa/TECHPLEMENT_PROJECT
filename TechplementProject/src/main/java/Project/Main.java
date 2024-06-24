package Project;
import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class combines functionalities for text manipulation, file encryption/decryption,
 * and file compression into a single command-line interface.
 */
public class Main {

    /**
     * Main method that presents a menu-driven interface to the user.
     * Allows selecting between text manipulation, file encryption/decryption, file compression,
     * or exiting the program.
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\nSelect an operation:");
            System.out.println("1. Text Manipulation");
            System.out.println("2. File Encryption/Decryption");
            System.out.println("3. File Compression");
            System.out.println("4. Exit");

            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();  // Consume newline left-over

            switch(choice) {
                case 1:
                    textManipulation(scanner);
                    break;
                case 2:
                    fileEncryptionDecryption(scanner);
                    break;
                case 3:
                    fileCompression(scanner);
                    break;
                case 4:
                    System.out.println("Exiting...");
                    scanner.close();
                    return;
                default:
                    System.out.println("Thank you. Please try again.");
            }
        }
    }

    /**
     * Method for text manipulation operations: converting text to uppercase,
     * lowercase, counting words, and finding a pattern in the text.
     */
    public static void textManipulation(Scanner scanner) {
        System.out.print("Enter the text to manipulate: ");
        String text = scanner.nextLine();

        while (true) {
            System.out.println("\nSelect a text operation:");
            System.out.println("1. Convert to uppercase");
            System.out.println("2. Convert to lowercase");
            System.out.println("3. Count words");
            System.out.println("4. Find pattern");
            System.out.println("5. Back to main menu");

            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();  // Consume newline left-over

            switch(choice) {
                case 1:
                    System.out.println("Uppercase: " + toUppercase(text));
                    break;
                case 2:
                    System.out.println("Lowercase: " + toLowercase(text));
                    break;
                case 3:
                    System.out.println("Word count: " + wordCount(text));
                    break;
                case 4:
                    System.out.print("Enter the pattern to find: ");
                    String pattern = scanner.nextLine();
                    System.out.println("Pattern found: " + findPattern(text, pattern));
                    break;
                case 5:
                    return; // Return to main menu
                default:
                    System.out.println("Invalid choice. Please try again.");
            }
        }
    }

    /**
     * Converts the given text to uppercase.
     */
    public static String toUppercase(String text) {
        return text.toUpperCase();
    }

    /**
     * Converts the given text to lowercase.
     */
    public static String toLowercase(String text) {
        return text.toLowerCase();
    }

    /**
     * Counts the number of words in the given text.
     */
    public static int wordCount(String text) {
        String[] words = text.split("\\s+");
        return words.length;
    }

    /**
     * Finds if the given pattern exists in the text.
     * Returns true if found, false otherwise.
     */
    public static boolean findPattern(String text, String pattern) {
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(text);
        return m.find();
    }

    /**
     * Method for file encryption/decryption operations.
     * Allows encrypting or decrypting a file using AES encryption algorithm.
     */
    public static void fileEncryptionDecryption(Scanner scanner) {
        System.out.println("Enter the path of the file to encrypt/decrypt:");
        String filePath = scanner.nextLine();
        System.out.println("Enter the password:");
        String password = scanner.nextLine();

        System.out.println("Do you want to (E)ncrypt or (D)ecrypt?");
        String action = scanner.nextLine().toUpperCase();

        try {
            File inputFile = new File(filePath);
            File outputFile;
            if (action.equals("E")) {
                outputFile = new File(filePath + ".enc");
                encryptFile(password, inputFile, outputFile);
                System.out.println("File encrypted successfully.");
            } else if (action.equals("D")) {
                if (!filePath.endsWith(".enc")) {
                    System.out.println("File extension should be .enc for decryption.");
                    return;
                }
                outputFile = new File(filePath.replace(".enc", ""));
                decryptFile(password, inputFile, outputFile);
                System.out.println("File decrypted successfully.");
            } else {
                System.out.println("Invalid action. Please enter E or D.");
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    /**
     * Encrypts the given inputFile using AES encryption with the provided password.
     * Writes the encrypted content to the outputFile.
     */
    private static void encryptFile(String password, File inputFile, File outputFile) throws Exception {
        SecretKey secretKey = generateKey(password);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());
        byte[] outputBytes = cipher.doFinal(inputBytes);

        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(outputBytes);
        }
    }

    /**
     * Decrypts the given inputFile (assumed to be encrypted) using AES decryption with the provided password.
     * Writes the decrypted content to the outputFile.
     */
    private static void decryptFile(String password, File inputFile, File outputFile) throws Exception {
        SecretKey secretKey = generateKey(password);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());
        byte[] outputBytes = cipher.doFinal(inputBytes);

        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(outputBytes);
        }
    }

    /**
     * Generates a SecretKey using the SHA-1 hash of the provided password,
     * ensuring it's compatible with AES encryption.
     */
    private static SecretKey generateKey(String password) throws Exception {
        byte[] key = password.getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16); // use only first 128 bit
        return new SecretKeySpec(key, "AES");
    }

    /**
     * Method for file compression operation.
     * Compresses the specified inputFile into a ZIP archive at the specified outputZipFilePath.
     */
    public static void fileCompression(Scanner scanner) {
        System.out.print("Enter the path of the file to compress: ");
        String inputFilePath = scanner.nextLine();

        System.out.print("Enter the path for the output zip file: ");
        String outputZipFilePath = scanner.nextLine();

        try {
            compressFileToZip(inputFilePath, outputZipFilePath);
            System.out.println("File compressed successfully to " + outputZipFilePath);
        } catch (IOException e) {
            System.err.println("Error compressing file: " + e.getMessage());
        }
    }

    /**
     * Compresses the specified inputFile into a ZIP archive at the specified outputZipFilePath.
     */
    public static void compressFileToZip(String inputFilePath, String outputZipFilePath) throws IOException {
        // Create file input stream to read the input file
        try (FileInputStream fis = new FileInputStream(inputFilePath);
             // Create file output stream to write to the ZIP file
             FileOutputStream fos = new FileOutputStream(outputZipFilePath);
             // Wrap the output stream with a ZIP output stream
             ZipOutputStream zos = new ZipOutputStream(fos)) {

            // Create a new ZIP entry for the file
            ZipEntry zipEntry = new ZipEntry(new File(inputFilePath).getName());
            zos.putNextEntry(zipEntry);

            // Buffer for reading the input file
            byte[] buffer = new byte[1024];
            int bytesRead;

            // Read the input file and write to the ZIP file
            while ((bytesRead = fis.read(buffer)) != -1) {
                zos.write(buffer, 0, bytesRead);
            }

            // Close the ZIP entry
            zos.closeEntry();
        }
    }
}
