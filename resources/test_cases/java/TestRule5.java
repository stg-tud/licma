import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

class TestRule5 {

    int field1 = 999;
    int field2 = 1000;

    /**
     * Positive: pExample1HardCoded, initialize PBEKeySpec and PBEParameterSpec with an iteration count < 1000
     */
    public byte[] pExample1HardCoded(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 999);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 999);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample2LocalVariable, initialize PBEKeySpec and PBEParameterSpec with an iteration count < 1000
     */
    public byte[] pExample2LocalVariable(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int iterationCount = 999;
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample3NestedLocalVariable, nested local variable initialization
     */
    public byte[] pExample3NestedLocalVariable(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int iterationCount1 = 999;
        int iterationCount2 = iterationCount1;
        int iterationCount3 = iterationCount2;

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount3);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount3);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample4DirectFieldAccess
     */
    public byte[] pExample4DirectFieldAccess(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, field1);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, field1);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample5IndirectFieldAccess
     */
    public byte[] pExample5IndirectFieldAccess(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int iterationCount = field1;

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Positive: pExample6MethodCall
     */
    public byte[] pExample6MethodCall(byte[] plaintext, String password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Belongs to pExample6MethodCall
     * Positive: pExample6NestedMethodCall
     */
    public byte[] pExample6NestedMethodCall(byte[] plaintext, String password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return pExample6MethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Belongs to pExample6MethodCall
     * Positive: pExample6DirectMethodCall
     */
    public byte[] pExample6DirectMethodCall(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int iterationCount = 999;

        return pExample6MethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Belongs to pExample6MethodCall
     * Positive: pExample6NestedMethodCallCaller
     */
    public byte[] pExample6NestedMethodCallCaller(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int iterationCount = 999;

        return pExample6NestedMethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Positive: pExample7WarningParameterNotResolvable
     */
    public byte[] pExample7WarningParameterNotResolvable(byte[] plaintext, String password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExample1, initialize PBEKeySpec and PBEParameterSpec with a iteration count >= 1000
     */
    public byte[] nExample1HardCoded(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 1000);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 1000);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExample2LocalVariable, initialize PBEKeySpec and PBEParameterSpec with a iteration count >= 1000
     */
    public byte[] nExample2LocalVariable(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int iterationCount = 1000;
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExample3NestedLocalVariable
     */
    public byte[] nExample3NestedLocalVariable(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int iterationCount1 = 1000;
        int iterationCount2 = iterationCount1;
        int iterationCount3 = iterationCount2;

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount3);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount3);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExample4DirectFieldAccess
     */
    public byte[] nExample4DirectFieldAccess(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, field2);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, field2);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Negative: nExample5IndirectFieldAccess
     */
    public byte[] nExample5IndirectFieldAccess(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int iterationCount = field2;

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Belongs to pExample6MethodCall
     * Negative: nExample6DirectMethodCall
     */
    public byte[] nExample6DirectMethodCall(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int iterationCount = 1000;

        return pExample6MethodCall(plaintext, password, salt, iterationCount);
    }

    /**
     * Belongs to pExample6MethodCall
     * Negative: nExample6NestedMethodCallCaller
     */
    public byte[] nExample6NestedMethodCallCaller(byte[] plaintext, String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int iterationCount = 1000;

        return pExample6NestedMethodCall(plaintext, password, salt, iterationCount);
    }

    public static void main(String[] args) {
        System.out.println("TestRule5");
    }
}