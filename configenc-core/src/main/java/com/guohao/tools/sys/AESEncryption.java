package com.guohao.tools.sys;

import com.guohao.EncryptionAlgorithm;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

// AES-GCM 加密实现
public class AESEncryption implements EncryptionAlgorithm {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int VERSION = 1;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    @Override
    public byte[] encrypt(byte[] data, String key) throws Exception {
        try (ByteArrayInputStream in = new ByteArrayInputStream(data);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            encrypt(in, out, key);
            return out.toByteArray();
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, String key) throws Exception {
        try (ByteArrayInputStream in = new ByteArrayInputStream(encryptedData);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            decrypt(in, out, key);
            return out.toByteArray();
        }
    }

    @Override
    public void encrypt(java.io.InputStream input, java.io.OutputStream output, String key) throws Exception {
        SecretKey secretKey = parseKey(key);
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        DataOutputStream dataOut = new DataOutputStream(output);
        dataOut.writeByte(VERSION);
        dataOut.writeByte(iv.length);
        dataOut.write(iv);
        dataOut.flush();

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_BITS, iv));
        try (CipherOutputStream cipherOut = new CipherOutputStream(output, cipher)) {
            input.transferTo(cipherOut);
        }
    }

    @Override
    public void decrypt(java.io.InputStream input, java.io.OutputStream output, String key) throws Exception {
        DataInputStream dataIn = new DataInputStream(input);
        int version = dataIn.readUnsignedByte();
        if (version != VERSION) {
            throw new IllegalArgumentException("Unsupported AES-GCM payload version: " + version);
        }
        int ivLen = dataIn.readUnsignedByte();
        if (ivLen <= 0 || ivLen > 32) {
            throw new IllegalArgumentException("Invalid IV length: " + ivLen);
        }
        byte[] iv = new byte[ivLen];
        dataIn.readFully(iv);

        SecretKey secretKey = parseKey(key);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_BITS, iv));
        try (CipherInputStream cipherIn = new CipherInputStream(dataIn, cipher)) {
            cipherIn.transferTo(output);
        }
    }

    @Override
    public String getAlgorithmName() {
        return "AES-GCM";
    }

    public static String generateKeyBase64() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    private static SecretKey parseKey(String key) throws Exception {
        if (key == null || key.trim().isEmpty()) {
            throw new IllegalArgumentException("AES key is required (Base64)");
        }
        byte[] rawKey = decodeKey(key.trim());
        byte[] normalized = normalizeKey(rawKey);
        return new SecretKeySpec(normalized, ALGORITHM);
    }

    private static byte[] decodeKey(String key) {
        try {
            return Base64.getDecoder().decode(key.getBytes(StandardCharsets.US_ASCII));
        } catch (IllegalArgumentException ex) {
            return key.getBytes(StandardCharsets.UTF_8);
        }
    }

    private static byte[] normalizeKey(byte[] rawKey) throws Exception {
        int len = rawKey.length;
        if (len == 16 || len == 24 || len == 32) {
            return rawKey;
        }
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(rawKey);
    }
}
