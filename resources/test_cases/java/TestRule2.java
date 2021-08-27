import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

class TestRule2 {

    byte[] field1 = "1234567812345678".getBytes(StandardCharsets.UTF_8);
    byte[] field2 = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
    byte[] field3 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

    /**
     * Positive: pExample1HardCoded, initialize IvParameterSpec with a string
     */
    public byte[] pExample1HardCoded(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec("1234567812345678".getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample2HardCoded, initialize IvParameterSpec with an array 1
     */
    public byte[] pExample2HardCoded(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[] {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'});
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample3HardCoded, initialize IvParameterSpec with an array 2
     */
    public byte[] pExample3HardCoded(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[] {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08});
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample4LocalVariable, local variable initialization with a string
     */
    public byte[] pExample4LocalVariable(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = "1234567812345678".getBytes(StandardCharsets.UTF_8);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample5LocalVariable, local variable initialization with an array 1
     */
    public byte[] pExample5LocalVariable(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample6LocalVariable, local variable initialization with an array 2
     */
    public byte[] pExample6LocalVariable(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample7NestedLocalVariable, nested local variable initialization with a string
     */
    public byte[] pExample7NestedLocalVariable(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv1 = "1234567812345678".getBytes(StandardCharsets.UTF_8);
        byte[] iv2 = iv1;
        byte[] iv3 = iv2;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv3);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample8NestedLocalVariable, nested local variable initialization with an array 1
     */
    public byte[] pExample8NestedLocalVariable(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv1 = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
        byte[] iv2 = iv1;
        byte[] iv3 = iv2;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv3);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample9NestedLocalVariable, nested local variable initialization with an array 2
     */
    public byte[] pExample9NestedLocalVariable(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv1 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        byte[] iv2 = iv1;
        byte[] iv3 = iv2;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv3);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample10DirectFieldAccess (string)
     */
    public byte[] pExample10DirectFieldAccess(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(field1);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample11DirectFieldAccess (array 1)
     */
    public byte[] pExample11DirectFieldAccess(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(field2);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample12DirectFieldAccess (array 2)
     */
    public byte[] pExample12DirectFieldAccess(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(field3);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample13IndirectFieldAccess (string)
     */
    public byte[] pExample13IndirectFieldAccess(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = field1;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample14IndirectFieldAccess (array 1)
     */
    public byte[] pExample14IndirectFieldAccess(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = field2;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample15IndirectFieldAccess (array 2)
     */
    public byte[] pExample15IndirectFieldAccess(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = field3;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample16MethodCall
     */
    public byte[] pExample16MethodCall(byte[] plaintext, SecretKey key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCall
     */
    public byte[] pExample16NestedMethodCall(byte[] plaintext, SecretKey key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return pExample16MethodCall(plaintext, key, iv);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16DirectMethodCallString (string)
     */
    public byte[] pExample16DirectMethodCallString(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = "1234567812345678".getBytes(StandardCharsets.UTF_8);
        return pExample16MethodCall(plaintext, key, iv);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16DirectMethodCallArray1 (array 1)
     */
    public byte[] pExample16DirectMethodCallArray1(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
        return pExample16MethodCall(plaintext, key, iv);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16DirectMethodCallArray2 (array 2)
     */
    public byte[] pExample16DirectMethodCallArray2(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        return pExample16MethodCall(plaintext, key, iv);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCallString (string)
     */
    public byte[] pExample16NestedMethodCallString(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = "1234567812345678".getBytes(StandardCharsets.UTF_8);
        return pExample16NestedMethodCall(plaintext, key, iv);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCallArray1 (array 1)
     */
    public byte[] pExample16NestedMethodCallArray1(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
        return pExample16NestedMethodCall(plaintext, key, iv);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCallArray2 (array 2)
     */
    public byte[] pExample16NestedMethodCallArray2(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        return pExample16NestedMethodCall(plaintext, key, iv);
    }

    /**
     * Positive: pExample17WarningParameterNotResolvable
     */
    public byte[] pExample17WarningParameterNotResolvable(byte[] plaintext, SecretKey key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExample1RandomIV
     */
    public byte[] nExample1RandomIV(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] ivRandom = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivRandom);

        return pExample16MethodCall(plaintext, key, ivRandom);
    }

    public static void main(String[] args) {
        System.out.println("TestRule2");
    }
}