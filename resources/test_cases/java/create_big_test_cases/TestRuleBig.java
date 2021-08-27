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


}