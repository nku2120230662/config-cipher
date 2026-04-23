package com.guohao;

// 1. 加密算法接口
public interface EncryptionAlgorithm {
    byte[] encrypt(byte[] data, String key) throws Exception;
    byte[] decrypt(byte[] encryptedData, String key) throws Exception;
    String getAlgorithmName();

    default void encrypt(java.io.InputStream input, java.io.OutputStream output, String key) throws Exception {
        byte[] data = input.readAllBytes();
        byte[] encrypted = encrypt(data, key);
        output.write(encrypted);
    }

    default void decrypt(java.io.InputStream input, java.io.OutputStream output, String key) throws Exception {
        byte[] data = input.readAllBytes();
        byte[] decrypted = decrypt(data, key);
        output.write(decrypted);
    }
}
