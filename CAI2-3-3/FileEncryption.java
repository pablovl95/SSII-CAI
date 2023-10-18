import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.Key;

public class FileEncryption {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("1. Crear un Almacen a partir de Archivo.txt, sobrescribiendo datos en Almacen.txt (c)\n");
        System.out.print("2. Descifrar el Almacen (d)\n");
        System.out.print("3. Añadir clave a el Almacen (a)\n");
        System.out.print("4. Test de prueba CAI (t)\n");
        System.out.print("Elija una opcion: ");
        String choice = scanner.nextLine();

        if ("c".equalsIgnoreCase(choice)) {
            System.out.print("Ingresa la clave para cifrar[vacio para generar una aleatoria]: ");
            String key = scanner.nextLine();
            if (key == "") {
                key = generarContrasena(32);
                System.out.println("Su contraseña es: "+key);
            }
            encryptFile("Archivo.txt", "Almacen.txt", key);
        } else if ("d".equalsIgnoreCase(choice)) {
            System.out.print("Ingresa la clave para descifrar: ");
            String key = scanner.nextLine();
            System.out.print("Ingresa la contraseña que desea consultar: ");
            String keyAs = scanner.nextLine();
            
            String outputDes = decryptFile("Almacen.txt", key);
            System.out.println(outputDes);
            String FinallyOutput = KeyShow(outputDes, keyAs);
            System.out.println("Clave consultada: "+ FinallyOutput);
        } else if ("a".equalsIgnoreCase(choice)) {
            System.out.print("Ingresa la clave para descifrar el almacen: ");
            String key = scanner.nextLine();
            System.out.print("Ingresa el campo que desea añadir: ");
            String keyAs = scanner.nextLine();
            System.out.print("Ingresa la clave que desea añadir en el respectivo campo: ");
            String value = scanner.nextLine();
            agregarClave("Almacen.txt", key, keyAs,value);
        }else if ("t".equalsIgnoreCase(choice)){
             System.out.print("Ingresa la clave para descifrar el almacen: ");
            String key = scanner.nextLine();
            System.out.print("Ingresa el campo que desea añadir: ");
            String keyAs = scanner.nextLine();
            System.out.print("Ingresa la clave que desea añadir en el respectivo campo: ");
            String value = scanner.nextLine();
            agregarClave("Almacen.txt", key, keyAs,value);
            String outputDes = decryptFile("Almacen.txt", key);
            String FinallyOutput = KeyShow(outputDes, keyAs);
            encryptFile("imagen.jpg", "imagen_cifrada.jpg", FinallyOutput);
        }
        else{
             System.out.print("El dato insertado no es una opcion valida");
        }

        scanner.close();
    }

    public static String decryptFile(String encryptedFile, String key) {
        try {
            FileInputStream inFile = new FileInputStream(encryptedFile);

            byte[] keyValue = key.getBytes();
            Key secretKey = new SecretKeySpec(keyValue, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            byte[] iv = new byte[16];
            inFile.read(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] inputBytes = new byte[64];
            int bytesRead;

            while ((bytesRead = inFile.read(inputBytes)) != -1) {
                byte[] outputBytes = cipher.update(inputBytes, 0, bytesRead);
                if (outputBytes != null) {
                    outputStream.write(outputBytes);
                }
            }

            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                outputStream.write(outputBytes);
            }

            inFile.close();

            return new String(outputStream.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String KeyShow(String Output, String keyAs) {
        String[] keyValuePairs = Output.split(",");

        for (String pair : keyValuePairs) {
            String[] keyValue = pair.split(":");
            if (keyValue.length == 2) {
                String key = keyValue[0].trim();
                String value = keyValue[1].trim();
                if (key.equals(keyAs)) {
                    return value;
                }
            }
        }

        return null; // Devuelve null si no se encontró la clave
    }
    public static String generarContrasena(int longitud) {
        String caracteres = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+=";
        StringBuilder contrasena = new StringBuilder();

        SecureRandom random = new SecureRandom();

        for (int i = 0; i < longitud; i++) {
            int index = random.nextInt(caracteres.length());
            char caracter = caracteres.charAt(index);
            contrasena.append(caracter);
        }

        return contrasena.toString();
    }
    public static void encryptFile(String inputFile, String encryptedFile, String key) {
        try {
            FileInputStream inFile = new FileInputStream(inputFile);
            FileOutputStream outFile = new FileOutputStream(encryptedFile);

            byte[] keyValue = key.getBytes();
            Key secretKey = new SecretKeySpec(keyValue, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            byte[] iv = new byte[16];
            new java.security.SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            outFile.write(iv);

            byte[] inputBytes = new byte[64];
            int bytesRead;

            while ((bytesRead = inFile.read(inputBytes)) != -1) {
                byte[] outputBytes = cipher.update(inputBytes, 0, bytesRead);
                if (outputBytes != null) {
                    outFile.write(outputBytes);
                }
            }

            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                outFile.write(outputBytes);
            }

            inFile.close();
            outFile.close();

            System.out.println("Archivo cifrado con éxito.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static void agregarClave(String encryptedFile, String key, String clave, String valor) {
        try {
            String contenidoCifrado = decryptFile(encryptedFile, key);
            String nuevoContenido = contenidoCifrado + "," + clave + ":" + valor;
            
            // Crear un archivo temporal
            String archivoTemporal = "ar.txt";
            File tempFile = new File(archivoTemporal);
            if (!tempFile.exists()) {
                tempFile.createNewFile();
            }
            
            // Escribir el nuevo contenido en el archivo temporal
            try (FileWriter writer = new FileWriter(tempFile)) {
                writer.write(nuevoContenido);
            } catch (IOException e) {
                e.printStackTrace();
            }
            
            // Cifrar el archivo temporal y sobrescribir el archivo original
            encryptFile(archivoTemporal, encryptedFile, key);
            
            // Borrar el archivo temporal
            if (tempFile.exists()) {
                tempFile.delete();
            } else {
                System.out.println("Algo ha salido mal");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}