import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

class TestRule4 {

    byte[] field1 = "12345678".getBytes(StandardCharsets.UTF_8);
    byte[] field2 = {'1', '2', '3', '4', '5', '6', '7', '8'};
    byte[] field3 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

    /**
     * Positive: pExample1HardCoded, initialize PBEKeySpec and PBEParameterSpec with a string
     */
    public byte[] pExample1HardCoded(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), "12345678".getBytes(StandardCharsets.UTF_8), iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec("12345678".getBytes(StandardCharsets.UTF_8), iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample2HardCoded, initialize PBEKeySpec and PBEParameterSpec with an array 1
     */
    public byte[] pExample2HardCoded(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), new byte[]{'1', '2', '3', '4', '5', '6', '7', '8'}, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(new byte[]{'1', '2', '3', '4', '5', '6', '7', '8'}, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample3HardCoded, initialize PBEKeySpec and PBEParameterSpec with an array 2
     */
    public byte[] pExample3HardCoded(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08}, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08}, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample4LocalVariable
     */
    public byte[] pExample4LocalVariable(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = "12345678".getBytes(StandardCharsets.UTF_8);

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample5LocalVariable
     */
    public byte[] pExample5LocalVariable(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample6LocalVariable
     */
    public byte[] pExample6LocalVariable(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample7NestedLocalVariable, nested local variable initialization with a string
     */
    public byte[] pExample7NestedLocalVariable(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt1 = "12345678".getBytes(StandardCharsets.UTF_8);
        byte[] salt2 = salt1;
        byte[] salt3 = salt2;

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt3, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt3, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample8NestedLocalVariable, nested local variable initialization with an array 1
     */
    public byte[] pExample8NestedLocalVariable(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt1 = {'1', '2', '3', '4', '5', '6', '7', '8'};
        byte[] salt2 = salt1;
        byte[] salt3 = salt2;

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt3, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt3, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample9NestedLocalVariable, nested local variable initialization with an array 2
     */
    public byte[] pExample9NestedLocalVariable(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt1 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        byte[] salt2 = salt1;
        byte[] salt3 = salt2;

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt3, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt3, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample10DirectFieldAccess (string)
     */
    public byte[] pExample10DirectFieldAccess(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), field1, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(field1, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample11DirectFieldAccess (array 1)
     */
    public byte[] pExample11DirectFieldAccess(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), field2, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(field2, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample12DirectFieldAccess (array 2)
     */
    public byte[] pExample12DirectFieldAccess(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), field3, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(field3, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample13IndirectFieldAccess (string)
     */
    public byte[] pExample13IndirectFieldAccess(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = field1;

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample14IndirectFieldAccess (array 1)
     */
    public byte[] pExample14IndirectFieldAccess(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = field2;

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample15IndirectFieldAccess (array 2)
     */
    public byte[] pExample15IndirectFieldAccess(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = field3;

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample16MethodCall
     */
    public byte[] pExample16MethodCall(byte[] plaintext, String password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCall
     */
    public byte[] pExample16NestedMethodCall(byte[] plaintext, String password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return pExample16MethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16DirectMethodCallString
     */
    public byte[] pExample16DirectMethodCallString(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = "12345678".getBytes(StandardCharsets.UTF_8);

        return pExample16MethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16DirectMethodCallArray1
     */
    public byte[] pExample16DirectMethodCallArray1(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        return pExample16MethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16DirectMethodCallArray2
     */
    public byte[] pExample16DirectMethodCallArray2(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        return pExample16MethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCallString
     */
    public byte[] pExample16NestedMethodCallString(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = "12345678".getBytes(StandardCharsets.UTF_8);

        return pExample16NestedMethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCallArray1
     */
    public byte[] pExample16NestedMethodCallArray1(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        return pExample16NestedMethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCallArray2
     */
    public byte[] pExample16NestedMethodCallArray2(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] salt = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        return pExample16NestedMethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Positive: pExample17WarningParameterNotResolvable
     */
    public byte[] pExample17WarningParameterNotResolvable(byte[] plaintext, String password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExample1RandomSalt
     */
    public byte[] nExample1RandomSalt(byte[] plaintext, String password, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[8];
        random.nextBytes(salt);

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    public static void main(String[] args) {
        System.out.println("TestRule4");
    }
}