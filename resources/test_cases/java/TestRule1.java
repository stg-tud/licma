import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

class TestRule1 {

    String field1 = "AES";
    String field2 = "AES/CBC/PKCS5Padding";

    /**
     * Positive: pExample1HardCoded
     */
    public byte[] pExample1HardCoded(byte[] plaintext, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample2HardCoded
     */
    public byte[] pExample2HardCoded(byte[] plaintext, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample3LocalVariable
     */
    public byte[] pExample3LocalVariable(byte[] plaintext, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        String transformation = "AES/ECB/PKCS5Padding";
        System.out.println("AES/ECB/PKCS5Padding");
        String anotherTransformation = "AES/ECB/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample4MethodCall
     */
    public byte[] pExample4MethodCall(byte[] plaintext, SecretKey key, String transformation) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Belongs to pExample4MethodCall
     * Positive: pExample4NestedMethodCall
     */
    public byte[] pExample4NestedMethodCall(byte[] plaintext, SecretKey key, String transformation) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return pExample4MethodCall(plaintext, key, transformation);
    }

    /**
     * Belongs to pExample4MethodCall
     * Positive: pExample4, method parameter; example4ParameterWithECB, example4NestedCall1, example4NestedCall2
     */
    public byte[] pExample4DirectMethodCall(byte[] plaintext, SecretKey key) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        String transformation = "AES/ECB/PKCS5Padding";

        return pExample4MethodCall(plaintext, key, transformation);
    }

    /**
     * Belongs to pExample4MethodCall
     * Positive: pExample4, method parameter; example4ParameterWithECB, example4NestedCall1, example4NestedCall2
     */
    public byte[] pExample4NestedMethodCallCaller(byte[] plaintext, SecretKey key) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        String transformation = "AES/ECB/PKCS5Padding";

        return pExample4NestedMethodCall(plaintext, key, transformation);
    }

    /**
     * Belongs to pExample4MethodCall
     * Positive: pExample4NestedMethodCallWithIndirectFieldAccess
     */
    public byte[] pExample4NestedMethodCallWithIndirectFieldAccess(byte[] plaintext, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        String transformation1 = field1;
        String transformation2 = transformation1;

        return pExample4NestedMethodCall(plaintext, key, transformation2);
    }

    /**
     * Positive: pExample5NestedLocalVariable
     */
    public byte[] pExample5NestedLocalVariable(byte[] plaintext, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        String transformation1 = "AES";
        String transformation2 = transformation1;
        String transformation3 = transformation2;
        Cipher cipher = Cipher.getInstance(transformation3);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample6DirectFieldAccess
     */
    public byte[] pExample6DirectFieldAccess(byte[] plaintext, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(field1);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample7IndirectFieldAccess
     */
    public byte[] pExample7IndirectFieldAccess(byte[] plaintext, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        String transformation1 = field1;
        String transformation2 = transformation1;
        Cipher cipher = Cipher.getInstance(transformation2);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample8WarningParameterNotResolvable
     */
    public byte[] pExample8WarningParameterNotResolvable(byte[] plaintext, SecretKey key, String transformation) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExample1PBE
     */
    public byte[] nExample1PBE(byte[] plaintext, String password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExample2CBC
     */
    public byte[] nExample2CBC(byte[] plaintext, SecretKey key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExmaple3CBCDirectFieldAccess
     */
    public byte[] nExmaple3CBCDirectFieldAccess(byte[] plaintext, SecretKey key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance(field2);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExmaple4CBCIndirectFieldAccess
     */
    public byte[] nExmaple4CBCIndirectFieldAccess(byte[] plaintext, SecretKey key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String transformation1 = field2;
        String transformation2 = transformation1;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance(transformation2);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(plaintext);
    }

    public static void main(String[] args) {
        System.out.println("TestRule1");
    }
}