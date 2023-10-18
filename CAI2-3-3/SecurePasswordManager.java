import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.Key;
import java.util.Scanner;

public class SecurePasswordManager {
    private static final String keyFilePath = "key.txt"; // Ruta del archivo con la clave cifrada
    private static final String dataFilePath = "archivo_cifrado.txt"; // Ruta del archivo cifrado con los datos

    public static void main(String[] args) {
        String key;
        try {
            key = getKeyFromUser(); // Solicitar la clave de cifrado
            String decryptedData = decryptData(key);
            System.out.println("Datos descifrados: " + decryptedData);
            
            String service = getServiceFromUser();
            String password = getPasswordForService(decryptedData, service);
            if (password != null) {
                System.out.println("Contraseña para " + service + ": " + password);
            } else {
                System.out.println("El servicio no se encontró en los datos.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String getKeyFromUser() {
        System.out.print("Ingresa la clave para descifrar los datos: ");
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }

    private static String getServiceFromUser() {
        System.out.print("Ingresa el servicio para obtener la contraseña: ");
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }

    private static String decryptData(String key) throws Exception {
        String encryptedData = readDataFromFile(dataFilePath);
        return decrypt(encryptedData, key);
    }

    private static String decrypt(String encryptedText, String key) throws Exception {
        byte[] keyValue = key.getBytes();
        Key secretKey = new SecretKeySpec(keyValue, "AES");

        byte[] iv = new byte[16];
        System.arraycopy(encryptedText.getBytes(), 0, iv, 0, 16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] encryptedBytes = encryptedText.getBytes("UTF-8");
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes, 16, encryptedBytes.length - 16);

        return new String(decryptedBytes, "UTF-8");
    }

    private static String readDataFromFile(String filePath) throws IOException {
        StringBuilder data = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                data.append(line);
            }
        }
        return data.toString();
    }

    private static String getPasswordForService(String decryptedData, String service) {
        String[] entries = decryptedData.split(",");
        for (String entry : entries) {
            String[] parts = entry.split(":");
            if (parts.length == 2 && parts[0].trim().equalsIgnoreCase(service)) {
                return parts[1].trim();
            }
        }
        return null; // No se encontró el servicio
    }
}
