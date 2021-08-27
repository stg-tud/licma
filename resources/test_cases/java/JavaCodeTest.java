import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class JavaCodeTest {
    public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        TestRule1 testRule1 = new TestRule1();
        TestRule2 testRule2 = new TestRule2();
        TestRule3 testRule3 = new TestRule3();
        TestRule4 testRule4 = new TestRule4();
        TestRule5 testRule5 = new TestRule5();
        TestRule6 testRule6 = new TestRule6();

        byte[] plainText = "top secret!".getBytes(StandardCharsets.UTF_8);

        byte[] salt1 = "12345678".getBytes(StandardCharsets.UTF_8);
        byte[] salt2 = new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        byte[] iv1 = "1234567812345678".getBytes(StandardCharsets.UTF_8);
        byte[] iv2 = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
        byte[] iv3 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        byte[] seed = "12345678".getBytes(StandardCharsets.UTF_8);

        String password = "1234567812345678";

        int iterationCount1000 = 1000;
        int iterationCount999 = 999;

        String key1 = "1234567812345678";
        byte[] key2 = {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
        byte[] key3 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        SecretKeySpec secretKeySpec1 = new SecretKeySpec(key1.getBytes(StandardCharsets.UTF_8), "AES");
        SecretKeySpec secretKeySpec2 = new SecretKeySpec(key2, "AES");
        SecretKeySpec secretKeySpec3 = new SecretKeySpec(key3, "AES");

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // TestRule1
        // Positive tests
        test("TestRule1.pExample1HardCoded", plainText, decryptECB("AES", testRule1.pExample1HardCoded(plainText, secretKey), secretKey));
        test("TestRule1.pExample2HardCoded", plainText, decryptECB("AES/ECB/PKCS5Padding", testRule1.pExample2HardCoded(plainText, secretKey), secretKey));
        test("TestRule1.pExample3LocalVariable", plainText, decryptECB("AES/ECB/PKCS5Padding", testRule1.pExample3LocalVariable(plainText, secretKey), secretKey));
        test("TestRule1.pExample4DirectMethodCall", plainText, decryptECB("AES/ECB/PKCS5Padding", testRule1.pExample4DirectMethodCall(plainText, secretKey), secretKey));
        test("TestRule1.pExample4NestedMethodCallCaller", plainText, decryptECB("AES/ECB/PKCS5Padding", testRule1.pExample4NestedMethodCallCaller(plainText, secretKey), secretKey));
        test("TestRule1.pExample4NestedMethodCallWithIndirectFieldAccess", plainText, decryptECB("AES", testRule1.pExample4NestedMethodCallWithIndirectFieldAccess(plainText, secretKey), secretKey));
        test("TestRule1.pExample5NestedLocalVariable", plainText, decryptECB("AES", testRule1.pExample5NestedLocalVariable(plainText, secretKey), secretKey));
        test("TestRule1.pExample6DirectFieldAccess", plainText, decryptECB("AES/ECB/PKCS5Padding", testRule1.pExample6DirectFieldAccess(plainText, secretKey), secretKey));
        test("TestRule1.pExample7IndirectFieldAccess", plainText, decryptECB("AES/ECB/PKCS5Padding", testRule1.pExample7IndirectFieldAccess(plainText, secretKey), secretKey));
        test("TestRule1.pExample8WarningParameterNotResolvable", plainText, decryptECB("AES", testRule1.pExample8WarningParameterNotResolvable(plainText, secretKey, "AES"), secretKey));

        // TestRule1
        // Negative tests
        test("TestRule1.nExample1PBE", plainText, decryptPBE(testRule1.nExample1PBE(plainText, password, salt1, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule1.nExample2CBC", plainText, decryptCBC(testRule1.nExample2CBC(plainText, secretKey, iv1), secretKey, iv1));
        test("TestRule1.nExmaple3CBCDirectFieldAccess", plainText, decryptCBC(testRule1.nExmaple3CBCDirectFieldAccess(plainText, secretKey, iv1), secretKey, iv1));
        test("TestRule1.nExmaple4CBCIndirectFieldAccess", plainText, decryptCBC(testRule1.nExmaple4CBCIndirectFieldAccess(plainText, secretKey, iv1), secretKey, iv1));

        // TestRule2
        // Positive tests
        test("TestRule2.pExample1HardCoded", plainText, decryptCBC(testRule2.pExample1HardCoded(plainText, secretKey), secretKey, iv1));
        test("TestRule2.pExample2HardCoded", plainText, decryptCBC(testRule2.pExample2HardCoded(plainText, secretKey), secretKey, iv2));
        test("TestRule2.pExample3HardCoded", plainText, decryptCBC(testRule2.pExample3HardCoded(plainText, secretKey), secretKey, iv3));
        test("TestRule2.pExample4LocalVariable", plainText, decryptCBC(testRule2.pExample4LocalVariable(plainText, secretKey), secretKey, iv1));
        test("TestRule2.pExample5LocalVariable", plainText, decryptCBC(testRule2.pExample5LocalVariable(plainText, secretKey), secretKey, iv2));
        test("TestRule2.pExample6LocalVariable", plainText, decryptCBC(testRule2.pExample6LocalVariable(plainText, secretKey), secretKey, iv3));
        test("TestRule2.pExample7NestedLocalVariable", plainText, decryptCBC(testRule2.pExample7NestedLocalVariable(plainText, secretKey), secretKey, iv1));
        test("TestRule2.pExample8NestedLocalVariable", plainText, decryptCBC(testRule2.pExample8NestedLocalVariable(plainText, secretKey), secretKey, iv2));
        test("TestRule2.pExample9NestedLocalVariable", plainText, decryptCBC(testRule2.pExample9NestedLocalVariable(plainText, secretKey), secretKey, iv3));
        test("TestRule2.pExample10DirectFieldAccess", plainText, decryptCBC(testRule2.pExample10DirectFieldAccess(plainText, secretKey), secretKey, iv1));
        test("TestRule2.pExample11DirectFieldAccess", plainText, decryptCBC(testRule2.pExample11DirectFieldAccess(plainText, secretKey), secretKey, iv2));
        test("TestRule2.pExample12DirectFieldAccess", plainText, decryptCBC(testRule2.pExample12DirectFieldAccess(plainText, secretKey), secretKey, iv3));
        test("TestRule2.pExample13IndirectFieldAccess", plainText, decryptCBC(testRule2.pExample13IndirectFieldAccess(plainText, secretKey), secretKey, iv1));
        test("TestRule2.pExample14IndirectFieldAccess", plainText, decryptCBC(testRule2.pExample14IndirectFieldAccess(plainText, secretKey), secretKey, iv2));
        test("TestRule2.pExample15IndirectFieldAccess", plainText, decryptCBC(testRule2.pExample15IndirectFieldAccess(plainText, secretKey), secretKey, iv3));
        test("TestRule2.pExample16MethodCall", plainText, decryptCBC(testRule2.pExample16MethodCall(plainText, secretKey, iv1), secretKey, iv1));
        test("TestRule2.pExample16NestedMethodCall", plainText, decryptCBC(testRule2.pExample16NestedMethodCall(plainText, secretKey, iv1), secretKey, iv1));
        test("TestRule2.pExample16DirectMethodCallString", plainText, decryptCBC(testRule2.pExample16DirectMethodCallString(plainText, secretKey), secretKey, iv1));
        test("TestRule2.pExample16DirectMethodCallArray1", plainText, decryptCBC(testRule2.pExample16DirectMethodCallArray1(plainText, secretKey), secretKey, iv2));
        test("TestRule2.pExample16DirectMethodCallArray2", plainText, decryptCBC(testRule2.pExample16DirectMethodCallArray2(plainText, secretKey), secretKey, iv3));
        test("TestRule2.pExample16NestedMethodCallString", plainText, decryptCBC(testRule2.pExample16NestedMethodCallString(plainText, secretKey), secretKey, iv1));
        test("TestRule2.pExample16NestedMethodCallArray1", plainText, decryptCBC(testRule2.pExample16NestedMethodCallArray1(plainText, secretKey), secretKey, iv2));
        test("TestRule2.pExample16NestedMethodCallArray2", plainText, decryptCBC(testRule2.pExample16NestedMethodCallArray2(plainText, secretKey), secretKey, iv3));
        test("TestRule2.pExample17WarningParameterNotResolvable", plainText, decryptCBC(testRule2.pExample17WarningParameterNotResolvable(plainText, secretKey, iv1), secretKey, iv1));

        // TestRule2
        // Negative tests
        System.out.println("TestRule2.nExample1RandomIV: " + testRule2.nExample1RandomIV(plainText, secretKey) + "\n");

        // TestRule3
        // Positive tests
        test("TestRule3.pExample1HardCoded", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample1HardCoded(plainText), secretKeySpec1));
        test("TestRule3.pExample1HardCoded", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample2HardCoded(plainText), secretKeySpec2));
        test("TestRule3.pExample1HardCoded", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample3HardCoded(plainText), secretKeySpec3));
        test("TestRule3.pExample4LocalVariable", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample4LocalVariable(plainText), secretKeySpec1));
        test("TestRule3.pExample5LocalVariable", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample5LocalVariable(plainText), secretKeySpec2));
        test("TestRule3.pExample6LocalVariable", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample6LocalVariable(plainText), secretKeySpec3));
        test("TestRule3.pExample7NestedLocalVariable", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample7NestedLocalVariable(plainText), secretKeySpec1));
        test("TestRule3.pExample8NestedLocalVariable", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample8NestedLocalVariable(plainText), secretKeySpec2));
        test("TestRule3.pExample9NestedLocalVariable", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample9NestedLocalVariable(plainText), secretKeySpec3));
        test("TestRule3.pExample10DirectFieldAccess", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample10DirectFieldAccess(plainText), secretKeySpec1));
        test("TestRule3.pExample11DirectFieldAccess", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample11DirectFieldAccess(plainText), secretKeySpec2));
        test("TestRule3.pExample12DirectFieldAccess", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample12DirectFieldAccess(plainText), secretKeySpec3));
        test("TestRule3.pExample13IndirectFieldAccess", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample13IndirectFieldAccess(plainText), secretKeySpec1));
        test("TestRule3.pExample14IndirectFieldAccess", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample14IndirectFieldAccess(plainText), secretKeySpec2));
        test("TestRule3.pExample15IndirectFieldAccess", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample15IndirectFieldAccess(plainText), secretKeySpec3));
        test("TestRule3.pExample16MethodCallKeyString", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample16MethodCallKeyString(plainText, key1), secretKeySpec1));
        test("TestRule3.pExample16NestedMethodCallKeyString", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample16NestedMethodCallKeyString(plainText, key1), secretKeySpec1));
        test("TestRule3.pExample16DirectMethodCallKeyString", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample16DirectMethodCallKeyString(plainText), secretKeySpec1));
        test("TestRule3.pExample16NestedMethodCallKeyStringCaller", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample16NestedMethodCallKeyStringCaller(plainText), secretKeySpec1));
        test("TestRule3.pExample17MethodCall", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample17MethodCall(plainText, key1.getBytes(StandardCharsets.UTF_8)), secretKeySpec1));
        test("TestRule3.pExample17NestedMethodCall", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample17NestedMethodCall(plainText, key1.getBytes(StandardCharsets.UTF_8)), secretKeySpec1));
        test("TestRule3.pExample17DirectMethodCallString", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample17DirectMethodCallString(plainText), secretKeySpec1));
        test("TestRule3.pExample17DirectMethodCallArray1", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample17DirectMethodCallArray1(plainText), secretKeySpec2));
        test("TestRule3.pExample17DirectMethodCallArray2", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample17DirectMethodCallArray2(plainText), secretKeySpec3));
        test("TestRule3.pExample17NestedMethodCallString", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample17NestedMethodCallString(plainText), secretKeySpec1));
        test("TestRule3.pExample17NestedMethodCallArray1", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample17NestedMethodCallArray1(plainText), secretKeySpec2));
        test("TestRule3.pExample17NestedMethodCallArray2", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample17NestedMethodCallArray2(plainText), secretKeySpec3));
        test("TestRule3.pExample18WarningParameterNotResolvable", plainText, decryptECBSecretKeySpec("AES", testRule3.pExample18WarningParameterNotResolvable(plainText, key1), secretKeySpec1));

        // TestRule3
        // Negative tests
        System.out.println("TestRule3.nExample1KeyGenerator: " + testRule3.nExample1KeyGenerator(plainText) + "\n");

        // TestRule4
        // Positive tests
        test("TestRule4.pExample1HardCoded", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample1HardCoded(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample2HardCoded", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample2HardCoded(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample3HardCoded", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample3HardCoded(plainText, password, iterationCount1000), password, salt2, iterationCount1000));
        test("TestRule4.pExample4LocalVariable", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample4LocalVariable(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample5LocalVariable", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample5LocalVariable(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample6LocalVariable", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample6LocalVariable(plainText, password, iterationCount1000), password, salt2, iterationCount1000));
        test("TestRule4.pExample7NestedLocalVariable", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample7NestedLocalVariable(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample8NestedLocalVariable", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample8NestedLocalVariable(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample9NestedLocalVariable", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample9NestedLocalVariable(plainText, password, iterationCount1000), password, salt2, iterationCount1000));
        test("TestRule4.pExample10DirectFieldAccess", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample10DirectFieldAccess(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample11DirectFieldAccess", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample11DirectFieldAccess(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample12DirectFieldAccess", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample12DirectFieldAccess(plainText, password, iterationCount1000), password, salt2, iterationCount1000));
        test("TestRule4.pExample13IndirectFieldAccess", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample13IndirectFieldAccess(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample14IndirectFieldAccess", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample14IndirectFieldAccess(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample15IndirectFieldAccess", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample15IndirectFieldAccess(plainText, password, iterationCount1000), password, salt2, iterationCount1000));
        test("TestRule4.pExample16MethodCall", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample16MethodCall(plainText, password, salt1, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample16NestedMethodCall", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample16NestedMethodCall(plainText, password, salt1, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample16DirectMethodCallString", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample16DirectMethodCallString(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample16DirectMethodCallArray1", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample16DirectMethodCallArray1(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample16DirectMethodCallArray2", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample16DirectMethodCallArray2(plainText, password, iterationCount1000), password, salt2, iterationCount1000));
        test("TestRule4.pExample16NestedMethodCallString", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample16NestedMethodCallString(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample16NestedMethodCallArray1", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample16NestedMethodCallArray1(plainText, password, iterationCount1000), password, salt1, iterationCount1000));
        test("TestRule4.pExample16NestedMethodCallArray2", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample16NestedMethodCallArray2(plainText, password, iterationCount1000), password, salt2, iterationCount1000));
        test("TestRule4.pExample17WarningParameterNotResolvable", plainText, decryptPBE("PBEWithMD5AndDES", testRule4.pExample17WarningParameterNotResolvable(plainText, password, salt1, iterationCount1000), password, salt1, iterationCount1000));

        // TestRule4
        // Negative tests
        System.out.println("TestRule4.nExample1RandomSalt: " + testRule4.nExample1RandomSalt(plainText, password, iterationCount1000) + "\n");

        // TestRule5
        // Positive tests
        test("TestRule5.pExample1HardCoded", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.pExample1HardCoded(plainText, password, salt1), password, salt1, iterationCount999));
        test("TestRule5.pExample2LocalVariable", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.pExample2LocalVariable(plainText, password, salt1), password, salt1, iterationCount999));
        test("TestRule5.pExample3NestedLocalVariable", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.pExample3NestedLocalVariable(plainText, password, salt1), password, salt1, iterationCount999));
        test("TestRule5.pExample4DirectFieldAccess", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.pExample4DirectFieldAccess(plainText, password, salt1), password, salt1, iterationCount999));
        test("TestRule5.pExample5IndirectFieldAccess", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.pExample5IndirectFieldAccess(plainText, password, salt1), password, salt1, iterationCount999));
        test("TestRule5.pExample6MethodCall", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.pExample6MethodCall(plainText, password, salt1, iterationCount999), password, salt1, iterationCount999));
        test("TestRule5.pExample6NestedMethodCall", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.pExample6NestedMethodCall(plainText, password, salt1, iterationCount999), password, salt1, iterationCount999));
        test("TestRule5.pExample6DirectMethodCall", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.pExample6DirectMethodCall(plainText, password, salt1), password, salt1, iterationCount999));
        test("TestRule5.pExample6NestedMethodCallCaller", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.pExample6NestedMethodCallCaller(plainText, password, salt1), password, salt1, iterationCount999));
        test("TestRule5.pExample7WarningParameterNotResolvable", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.pExample7WarningParameterNotResolvable(plainText, password, salt1, iterationCount999), password, salt1, iterationCount999));

        // TestRule5
        // Negative tests
        test("TestRule5.nExample1HardCoded", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.nExample1HardCoded(plainText, password, salt1), password, salt1, iterationCount1000));
        test("TestRule5.nExample2LocalVariable", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.nExample2LocalVariable(plainText, password, salt1), password, salt1, iterationCount1000));
        test("TestRule5.nExample3NestedLocalVariable", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.nExample3NestedLocalVariable(plainText, password, salt1), password, salt1, iterationCount1000));
        test("TestRule5.nExample4DirectFieldAccess", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.nExample4DirectFieldAccess(plainText, password, salt1), password, salt1, iterationCount1000));
        test("TestRule5.nExample5IndirectFieldAccess", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.nExample5IndirectFieldAccess(plainText, password, salt1), password, salt1, iterationCount1000));
        test("TestRule5.nExample6DirectMethodCall", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.nExample6DirectMethodCall(plainText, password, salt1), password, salt1, iterationCount1000));
        test("TestRule5.nExample6NestedMethodCallCaller", plainText, decryptPBE("PBEWithMD5AndDES", testRule5.nExample6NestedMethodCallCaller(plainText, password, salt1), password, salt1, iterationCount1000));

        // TestRule6
        // Positive tests
        System.out.println("TestRule6.pExample1HardCoded: " + testRule6.pExample1HardCoded().nextInt() + "\n");
        System.out.println("TestRule6.pExample2HardCoded: " + testRule6.pExample2HardCoded().nextInt() + "\n");
        System.out.println("TestRule6.pExample3HardCoded: " + testRule6.pExample3HardCoded().nextInt() + "\n");
        System.out.println("TestRule6.pExample4LocalVariable: " + testRule6.pExample4LocalVariable().nextInt() + "\n");
        System.out.println("TestRule6.pExample5LocalVariable: " + testRule6.pExample5LocalVariable().nextInt() + "\n");
        System.out.println("TestRule6.pExample6LocalVariable: " + testRule6.pExample6LocalVariable().nextInt() + "\n");
        System.out.println("TestRule6.pExample7NestedLocalVariable: " + testRule6.pExample7NestedLocalVariable().nextInt() + "\n");
        System.out.println("TestRule6.pExample8NestedLocalVariable: " + testRule6.pExample8NestedLocalVariable().nextInt() + "\n");
        System.out.println("TestRule6.pExample9NestedLocalVariable: " + testRule6.pExample9NestedLocalVariable().nextInt() + "\n");
        System.out.println("TestRule6.pExample10DirectFieldAccess: " + testRule6.pExample10DirectFieldAccess().nextInt() + "\n");
        System.out.println("TestRule6.pExample11DirectFieldAccess: " + testRule6.pExample11DirectFieldAccess().nextInt() + "\n");
        System.out.println("TestRule6.pExample12DirectFieldAccess: " + testRule6.pExample12DirectFieldAccess().nextInt() + "\n");
        System.out.println("TestRule6.pExample13IndirectFieldAccess: " + testRule6.pExample13IndirectFieldAccess().nextInt() + "\n");
        System.out.println("TestRule6.pExample14IndirectFieldAccess: " + testRule6.pExample14IndirectFieldAccess().nextInt() + "\n");
        System.out.println("TestRule6.pExample15IndirectFieldAccess: " + testRule6.pExample15IndirectFieldAccess().nextInt() + "\n");
        System.out.println("TestRule6.pExample16MethodCall: " + testRule6.pExample16MethodCall(seed).nextInt() + "\n");
        System.out.println("TestRule6.pExample16NestedMethodCall: " + testRule6.pExample16NestedMethodCall(seed).nextInt() + "\n");
        System.out.println("TestRule6.pExample16DirectMethodCallString: " + testRule6.pExample16DirectMethodCallString().nextInt() + "\n");
        System.out.println("TestRule6.pExample16DirectMethodCallArray1: " + testRule6.pExample16DirectMethodCallArray1().nextInt() + "\n");
        System.out.println("TestRule6.pExample16DirectMethodCallArray2: " + testRule6.pExample16DirectMethodCallArray2().nextInt() + "\n");
        System.out.println("TestRule6.pExample16NestedMethodCallString: " + testRule6.pExample16NestedMethodCallString().nextInt() + "\n");
        System.out.println("TestRule6.pExample16NestedMethodCallArray1: " + testRule6.pExample16NestedMethodCallArray1().nextInt() + "\n");
        System.out.println("TestRule6.pExample16NestedMethodCallArray2: " + testRule6.pExample16NestedMethodCallArray2().nextInt() + "\n");
        System.out.println("TestRule6.pExample17WarningParameterNotResolvable: " + testRule6.pExample17WarningParameterNotResolvable(seed).nextInt() + "\n");

        // TestRule6
        // Negative tests
        System.out.println("TestRule6.nExample1NoSeedParameter: " + testRule6.nExample1NoSeedParameter().nextInt() + "\n");

    }

    public static byte[] decryptPBE(String algorithm, byte[] cipherText, String password, byte[] salt, int iterationCount) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(cipherText);
    }

    private static byte[] decryptECBSecretKeySpec(String algorithm, byte[] cipherText, SecretKeySpec secretKeySpec) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        return cipher.doFinal(cipherText);
    }

    private static byte[] decryptECB(String algorithm, byte[] cipherText, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    public static byte[] decryptPBE(byte[] cipherText, String password, byte[] salt, int iterationCount) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
        return cipher.doFinal(cipherText);
    }

    public static byte[] decryptCBC(byte[] cipherText, SecretKey key, byte[] iv) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(cipherText);
    }

    public static void test(String testName, byte[] plaintext, byte[] decryptionResult) {
        String strPlaintext = new String(plaintext);
        String strDecryptionResult = new String(decryptionResult);

        System.out.println(testName + " Plaintext: " + strPlaintext);
        System.out.println(testName + " Decryption result: " + strDecryptionResult);

        if (strDecryptionResult.startsWith(strPlaintext)) {
            System.out.println(testName + ": passed\n");
        } else {
            System.out.println(testName + ": failed\n");
        }
    }
}