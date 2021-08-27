package example.test.testtest.testtesttest;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

/**
 * Java code example for rule 1
 */
class ExampleCodeRule1 extends Test {

    /**
     * Positive example
     * ECB is selected by default.
     */
    public byte[] example1(byte[] plaintext, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive example
     * ECB is selected by method parameter(string).
     */
    public byte[] example2(byte[] plaintext, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive example
     * ECB is selected by method parameter(variable).
     */
    public byte[] example3(byte[] plaintext, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        String transformation = "AES/ECB/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive example
     * ECB is selected by method parameter(method parameter).
     */
    public byte[] example4(byte[] plaintext, SecretKey key, String transformation) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Negative example
     */
    public byte[] example5(byte[] plaintext, String password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Belongs to example4.
     * Passes transformation information via method parameter.
     */
    public void callExample4() throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        String transformation2 = "AES/ECB/PKCS5Padding";
        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        example4(plaintext, secretKey, transformation2);
    }

    public void callExample5(String transformationA) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        example4(plaintext, secretKey, transformationA);
    }

    public void callExample6() throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        String transformationB = "AES/ECB/PKCS5Padding";

        callExample5(transformationB);
    }

}

/**
 * Test
 */
public class TestRule1 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule2 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule3 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule4 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule5 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule6 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule7 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule8 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule9 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule10 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule11 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule12 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule13 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule14 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule15 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule16 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule17 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule18 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule19 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule20 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule21 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule22 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule23 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule24 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule25 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule26 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule27 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule28 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule29 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule30 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule31 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule32 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule33 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule34 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule35 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule36 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule37 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule38 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule39 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule40 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule41 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule42 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule43 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule44 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule45 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule46 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule47 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule48 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule49 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}

/**
 * Test
 */
public class TestRule50 {
    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}/** * Test */public class TestRule51 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule52 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule53 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule54 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule55 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule56 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule57 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule58 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule59 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule60 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule61 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule62 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule63 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule64 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule65 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule66 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule67 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule68 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule69 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule70 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule71 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule72 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule73 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule74 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule75 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule76 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule77 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule78 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule79 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule80 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule81 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule82 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule83 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule84 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule85 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule86 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule87 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule88 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule89 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule90 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule91 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule92 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule93 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule94 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule95 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule96 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule97 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule98 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule99 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule100 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule101 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule102 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule103 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule104 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule105 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule106 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule107 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule108 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule109 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule110 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule111 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule112 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule113 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule114 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule115 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule116 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule117 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule118 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule119 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule120 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule121 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule122 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule123 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule124 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule125 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule126 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule127 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule128 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule129 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule130 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule131 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule132 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule133 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule134 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule135 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule136 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule137 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule138 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule139 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule140 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule141 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule142 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule143 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule144 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule145 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule146 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule147 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule148 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule149 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule150 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule151 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule152 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule153 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule154 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule155 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule156 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule157 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule158 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule159 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule160 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule161 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule162 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule163 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule164 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule165 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule166 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule167 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule168 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule169 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule170 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule171 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule172 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule173 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule174 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule175 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule176 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule177 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule178 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule179 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule180 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule181 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule182 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule183 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule184 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule185 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule186 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule187 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule188 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule189 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule190 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule191 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule192 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule193 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule194 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule195 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule196 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule197 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule198 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule199 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule200 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule201 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule202 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule203 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule204 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule205 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule206 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule207 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule208 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule209 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule210 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule211 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule212 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule213 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule214 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule215 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule216 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule217 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule218 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule219 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule220 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule221 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule222 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule223 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule224 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule225 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule226 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule227 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule228 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule229 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule230 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule231 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule232 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule233 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule234 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule235 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule236 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule237 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule238 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule239 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule240 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule241 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule242 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule243 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule244 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule245 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule246 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule247 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule248 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule249 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule250 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule251 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule252 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule253 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule254 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule255 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule256 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule257 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule258 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule259 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule260 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule261 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule262 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule263 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule264 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule265 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule266 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule267 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule268 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule269 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule270 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule271 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule272 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule273 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule274 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule275 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule276 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule277 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule278 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule279 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule280 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule281 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule282 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule283 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule284 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule285 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule286 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule287 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule288 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule289 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule290 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule291 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule292 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule293 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule294 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule295 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule296 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule297 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule298 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule299 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule300 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule301 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule302 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule303 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule304 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule305 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule306 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule307 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule308 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule309 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule310 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule311 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule312 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule313 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule314 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule315 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule316 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule317 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule318 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule319 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule320 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule321 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule322 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule323 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule324 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule325 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule326 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule327 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule328 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule329 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule330 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule331 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule332 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule333 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule334 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule335 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule336 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule337 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule338 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule339 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule340 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule341 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule342 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule343 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule344 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule345 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule346 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule347 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule348 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule349 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
/** * Test */public class TestRule350 {    public static void main(String[] args) throws NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        ExampleCodeRule1 exampleCodeRule1 = new ExampleCodeRule1();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keySize = 128;
        keyGenerator.init(keySize);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] plaintext = "Test example code for rule 1.".getBytes(StandardCharsets.UTF_8);

        /**
         * Positive example
         */
        TestHelper.test("Test rule 1 example 1", plaintext, TestHelper.decrypt(exampleCodeRule1.example1(plaintext, secretKey), secretKey, "AES"));
        TestHelper.test("Test rule 1 example 2", plaintext, TestHelper.decrypt(exampleCodeRule1.example2(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 3", plaintext, TestHelper.decrypt(exampleCodeRule1.example3(plaintext, secretKey), secretKey, "AES/ECB/PKCS5Padding"));
        TestHelper.test("Test rule 1 example 4", plaintext, TestHelper.decrypt(exampleCodeRule1.example4(plaintext, secretKey, "AES/ECB/PKCS5Padding"), secretKey, "AES/ECB/PKCS5Padding"));

        String password = "topsecret";
        byte[] saltRandom = new byte[8];
        Random random = new SecureRandom();
        random.nextBytes(saltRandom);
        int iterationCount = 1000;
        /**
         * Negative example
         */
        TestHelper.test("Test rule 1 example 5", plaintext, TestHelper.decryptPBEWithConstantSalt(exampleCodeRule1.example5(plaintext, password, saltRandom, iterationCount), password, saltRandom, "PBEWithMD5AndDES", iterationCount));

    }


}
