import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class TestRule3 {

    byte[] field1 = "1234567812345678".getBytes(StandardCharsets.UTF_8);
    byte[] field2 = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
    byte[] field3 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

    /**
     * Positive: pExample1HardCoded, initialize SecretKeySpec with a string
     */
    public byte[] pExample1HardCoded(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec("1234567812345678".getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample2HardCoded, initialize SecretKeySpec with an array 1
     */
    public byte[] pExample2HardCoded(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[]{'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'}, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample3HardCoded, initialize SecretKeySpec with an array 2
     */
    public byte[] pExample3HardCoded(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08}, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample4LocalVariable, local variable initialization with a string
     */
    public byte[] pExample4LocalVariable(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = "1234567812345678".getBytes(StandardCharsets.UTF_8);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample5LocalVariable, local variable initialization with an array 1
     */
    public byte[] pExample5LocalVariable(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample6LocalVariable, local variable initialization with an array 2
     */
    public byte[] pExample6LocalVariable(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key1 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        byte[] key2 = key1;
        byte[] key3 = key2;

        SecretKeySpec secretKeySpec = new SecretKeySpec(key3, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample7NestedLocalVariable, nested local variable initialization with a string
     */
    public byte[] pExample7NestedLocalVariable(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key1 = "1234567812345678".getBytes(StandardCharsets.UTF_8);
        byte[] key2 = key1;
        byte[] key3 = key2;

        SecretKeySpec secretKeySpec = new SecretKeySpec(key3, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample8NestedLocalVariable, nested local variable initialization with an array 1
     */
    public byte[] pExample8NestedLocalVariable(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key1 = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
        byte[] key2 = key1;
        byte[] key3 = key2;

        SecretKeySpec secretKeySpec = new SecretKeySpec(key3, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample9NestedLocalVariable, nested local variable initialization with an array 2
     */
    public byte[] pExample9NestedLocalVariable(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key1 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        byte[] key2 = key1;
        byte[] key3 = key2;

        SecretKeySpec secretKeySpec = new SecretKeySpec(key3, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample10DirectFieldAccess (string)
     */
    public byte[] pExample10DirectFieldAccess(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(field1, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample11DirectFieldAccess (array 1)
     */
    public byte[] pExample11DirectFieldAccess(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(field2, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample12DirectFieldAccess (array 2)
     */
    public byte[] pExample12DirectFieldAccess(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(field3, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample13IndirectFieldAccess (string)
     */
    public byte[] pExample13IndirectFieldAccess(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = field1;
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample14IndirectFieldAccess (array 1)
     */
    public byte[] pExample14IndirectFieldAccess(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = field2;
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample15IndirectFieldAccess (array 2)
     */
    public byte[] pExample15IndirectFieldAccess(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = field3;
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample16MethodCallKeyString
     */
    public byte[] pExample16MethodCallKeyString(byte[] plaintext, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Belongs to pExample16MethodCallKeyString
     * Positive: pExample16NestedMethodCallKeyString
     */
    public byte[] pExample16NestedMethodCallKeyString(byte[] plaintext, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return pExample16MethodCallKeyString(plaintext, key);
    }

    /**
     * Belongs to pExample16MethodCallKeyString
     * Positive: pExample16DirectMethodCallKeyString
     */
    public byte[] pExample16DirectMethodCallKeyString(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String key = "1234567812345678";
        return pExample16MethodCallKeyString(plaintext, key);
    }

    /**
     * Belongs to pExample16MethodCallKeyString
     * Positive: pExample16NestedMethodCallKeyString
     */
    public byte[] pExample16NestedMethodCallKeyStringCaller(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String key = "1234567812345678";
        return pExample16NestedMethodCallKeyString(plaintext, key);
    }

    /**
     * Positive: pExample17MethodCall
     */
    public byte[] pExample17MethodCall(byte[] plaintext, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Belongs to pExample17MethodCall
     * Positive: pExample17NestedMethodCall
     */
    public byte[] pExample17NestedMethodCall(byte[] plaintext, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return pExample17MethodCall(plaintext, key);
    }

    /**
     * Belongs to pExample17MethodCall
     * Positive: pExample17DirectMethodCallString
     */
    public byte[] pExample17DirectMethodCallString(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = "1234567812345678".getBytes(StandardCharsets.UTF_8);
        return pExample17MethodCall(plaintext, key);
    }

    /**
     * Belongs to pExample17MethodCall
     * Positive: pExample17DirectMethodCallArray1
     */
    public byte[] pExample17DirectMethodCallArray1(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
        return pExample17MethodCall(plaintext, key);
    }

    /**
     * Belongs to pExample17MethodCall
     * Positive: pExample17DirectMethodCallArray2
     */
    public byte[] pExample17DirectMethodCallArray2(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        return pExample17MethodCall(plaintext, key);
    }

    /**
     * Belongs to pExample17MethodCall
     * Positive: pExample17NestedMethodCallString
     */
    public byte[] pExample17NestedMethodCallString(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = "1234567812345678".getBytes(StandardCharsets.UTF_8);
        return pExample17NestedMethodCall(plaintext, key);
    }

    /**
     * Belongs to pExample17MethodCall
     * Positive: pExample17NestedMethodCallArray1
     */
    public byte[] pExample17NestedMethodCallArray1(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
        return pExample17NestedMethodCall(plaintext, key);
    }

    /**
     * Belongs to pExample17MethodCall
     * Positive: pExample17NestedMethodCallArray2
     */
    public byte[] pExample17NestedMethodCallArray2(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        return pExample17NestedMethodCall(plaintext, key);
    }

    /**
     * Positive: pExample18WarningParameterNotResolvable
     */
    public byte[] pExample18WarningParameterNotResolvable(byte[] plaintext, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExample1KeyGenerator
     */
    public byte[] nExample1KeyGenerator(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKey secreteKey = KeyGenerator.getInstance("AES").generateKey();

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secreteKey);

        return cipher.doFinal(plaintext);
    }

    public static void main(String[] args) {
        System.out.println("TestRule3");
    }
}