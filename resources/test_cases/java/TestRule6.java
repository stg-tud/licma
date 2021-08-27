import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

class TestRule6 {

    byte[] field1 = "12345678".getBytes(StandardCharsets.UTF_8);
    byte[] field2 = {'1', '2', '3', '4', '5', '6', '7', '8'};
    byte[] field3 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

    /**
     * Positive: pExample1HardCoded
     */
    public SecureRandom pExample1HardCoded() {
        return new SecureRandom("12345678".getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Positive: pExample2HardCoded
     */
    public SecureRandom pExample2HardCoded() {
        return new SecureRandom(new byte[]{'1', '2', '3', '4', '5', '6', '7', '8'});
    }

    /**
     * Positive: pExample3HardCoded
     */
    public SecureRandom pExample3HardCoded() {
        return new SecureRandom(new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08});
    }

    /**
     * Positive: pExample4LocalVariable
     */
    public SecureRandom pExample4LocalVariable() {
        byte[] seed = "12345678".getBytes(StandardCharsets.UTF_8);

        return new SecureRandom(seed);
    }

    /**
     * Positive: pExample5LocalVariable
     */
    public SecureRandom pExample5LocalVariable() {
        byte[] seed = {'1', '2', '3', '4', '5', '6', '7', '8'};

        return new SecureRandom(seed);
    }

    /**
     * Positive: pExample6LocalVariable
     */
    public SecureRandom pExample6LocalVariable() {
        byte[] seed = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        return new SecureRandom(seed);
    }

    /**
     * Positive: pExample7NestedLocalVariable
     */
    public SecureRandom pExample7NestedLocalVariable() {
        byte[] seed1 = "12345678".getBytes(StandardCharsets.UTF_8);
        byte[] seed2 = seed1;
        byte[] seed3 = seed2;

        return new SecureRandom(seed3);
    }

    /**
     * Positive: pExample8NestedLocalVariable
     */
    public SecureRandom pExample8NestedLocalVariable() {
        byte[] seed1 = {'1', '2', '3', '4', '5', '6', '7', '8'};
        byte[] seed2 = seed1;
        byte[] seed3 = seed2;

        return new SecureRandom(seed3);
    }

    /**
     * Positive: pExample9NestedLocalVariable
     */
    public SecureRandom pExample9NestedLocalVariable() {
        byte[] seed1 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
        byte[] seed2 = seed1;
        byte[] seed3 = seed2;

        return new SecureRandom(seed3);
    }

    /**
     * Positive: pExample10DirectFieldAccess
     */
    public SecureRandom pExample10DirectFieldAccess() {
        return new SecureRandom(field1);
    }

    /**
     * Positive: pExample11DirectFieldAccess
     */
    public SecureRandom pExample11DirectFieldAccess() {
        return new SecureRandom(field2);
    }

    /**
     * Positive: pExample12DirectFieldAccess
     */
    public SecureRandom pExample12DirectFieldAccess() {
        return new SecureRandom(field3);
    }

    /**
     * Positive: pExample13IndirectFieldAccess
     */
    public SecureRandom pExample13IndirectFieldAccess() {
        byte[] seed = field1;

        return new SecureRandom(seed);
    }

    /**
     * Positive: pExample14IndirectFieldAccess
     */
    public SecureRandom pExample14IndirectFieldAccess() {
        byte[] seed = field2;

        return new SecureRandom(seed);
    }

    /**
     * Positive: pExample15IndirectFieldAccess
     */
    public SecureRandom pExample15IndirectFieldAccess() {
        byte[] seed = field3;

        return new SecureRandom(seed);
    }

    /**
     * Positive: pExample16MethodCall
     */
    public SecureRandom pExample16MethodCall(byte[] seed) {
        return new SecureRandom(seed);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16MethodCall
     */
    public SecureRandom pExample16NestedMethodCall(byte[] seed) {
        return pExample16MethodCall(seed);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16DirectMethodCallString
     */
    public SecureRandom pExample16DirectMethodCallString() {
        byte[] seed = "12345678".getBytes(StandardCharsets.UTF_8);

        return pExample16MethodCall(seed);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16DirectMethodCallArray1
     */
    public SecureRandom pExample16DirectMethodCallArray1() {
        byte[] seed = {'1', '2', '3', '4', '5', '6', '7', '8'};

        return pExample16MethodCall(seed);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16DirectMethodCallArray2
     */
    public SecureRandom pExample16DirectMethodCallArray2() {
        byte[] seed = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        return pExample16MethodCall(seed);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCallString
     */
    public SecureRandom pExample16NestedMethodCallString() {
        byte[] seed = "12345678".getBytes(StandardCharsets.UTF_8);

        return pExample16NestedMethodCall(seed);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCallArray1
     */
    public SecureRandom pExample16NestedMethodCallArray1() {
        byte[] seed = {'1', '2', '3', '4', '5', '6', '7', '8'};

        return pExample16NestedMethodCall(seed);
    }

    /**
     * Belongs to pExample16MethodCall
     * Positive: pExample16NestedMethodCallArray2
     */
    public SecureRandom pExample16NestedMethodCallArray2() {
        byte[] seed = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        return pExample16NestedMethodCall(seed);
    }

    /**
     * Positive: pExample17WarningParameterNotResolvable
     */
    public SecureRandom pExample17WarningParameterNotResolvable(byte[] seed) {
        return new SecureRandom(seed);
    }

    /**
     * Negative: nExample1NoSeedParameter
     */
    public SecureRandom nExample1NoSeedParameter() {
        return new SecureRandom();
    }

    public static void main(String[] args) {
        System.out.println("TestRule6");
    }
}