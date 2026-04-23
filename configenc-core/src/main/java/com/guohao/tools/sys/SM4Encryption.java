package com.guohao.tools.sys;

import com.guohao.EncryptionAlgorithm;
import com.guohao.tools.support.BouncyCastleSupport;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

// SM4-GCM 加密实现
public class SM4Encryption implements EncryptionAlgorithm {
    private static final String ALGORITHM = "SM4";
    private static final String TRANSFORMATION = "SM4/GCM/NoPadding";
    private static final int VERSION = 1;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final int KEY_BYTES = 16;

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
        BouncyCastleSupport.ensureProvider();
        byte[] keyBytes = normalizeKey(decodeKey(key), KEY_BYTES);
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        DataOutputStream dataOut = new DataOutputStream(output);
        dataOut.writeByte(VERSION);
        dataOut.writeByte(iv.length);
        dataOut.write(iv);
        dataOut.flush();

        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, ALGORITHM), new GCMParameterSpec(TAG_BITS, iv));
        try (CipherOutputStream cipherOut = new CipherOutputStream(output, cipher)) {
            input.transferTo(cipherOut);
        }
    }

    @Override
    public void decrypt(java.io.InputStream input, java.io.OutputStream output, String key) throws Exception {
        BouncyCastleSupport.ensureProvider();
        DataInputStream dataIn = new DataInputStream(input);
        int version = dataIn.readUnsignedByte();
        if (version != VERSION) {
            throw new IllegalArgumentException("Unsupported SM4-GCM payload version: " + version);
        }
        int ivLen = dataIn.readUnsignedByte();
        if (ivLen <= 0 || ivLen > 32) {
            throw new IllegalArgumentException("Invalid IV length: " + ivLen);
        }
        byte[] iv = new byte[ivLen];
        dataIn.readFully(iv);

        byte[] keyBytes = normalizeKey(decodeKey(key), KEY_BYTES);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, ALGORITHM), new GCMParameterSpec(TAG_BITS, iv));
        try (CipherInputStream cipherIn = new CipherInputStream(dataIn, cipher)) {
            cipherIn.transferTo(output);
        }
    }

    @Override
    public String getAlgorithmName() {
        return "SM4-GCM";
    }

    private static byte[] decodeKey(String key) {
        if (key == null || key.trim().isEmpty()) {
            throw new IllegalArgumentException("SM4 key is required (Base64)");
        }
        String trimmed = key.trim();
        try {
            return Base64.getDecoder().decode(trimmed.getBytes(StandardCharsets.US_ASCII));
        } catch (IllegalArgumentException ex) {
            return trimmed.getBytes(StandardCharsets.UTF_8);
        }
    }

    private static byte[] normalizeKey(byte[] rawKey, int targetLen) throws Exception {
        if (rawKey.length == targetLen) {
            return rawKey;
        }
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] digest = sha256.digest(rawKey);
        return Arrays.copyOf(digest, targetLen);
    }
}
