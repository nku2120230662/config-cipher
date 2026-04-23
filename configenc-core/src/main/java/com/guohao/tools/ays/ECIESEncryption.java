package com.guohao.tools.ays;

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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

// ECIES + AES-GCM 混合加密实现
public class ECIESEncryption implements EncryptionAlgorithm {
    private static final String EC_ALGORITHM = "EC";
    private static final String ECIES_CIPHER = "ECIES";
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int VERSION = 1;
    private static final int AES_KEY_BYTES = 32;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private KeyPair keyPair;

    public ECIESEncryption() throws Exception {
        generateKeyPair();
    }

    private void generateKeyPair() throws Exception {
        BouncyCastleSupport.ensureProvider();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EC_ALGORITHM, "BC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        this.keyPair = keyGen.generateKeyPair();
    }

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
        KeyMaterial material = resolveKeyMaterial(key);
        if (material.publicKey == null) {
            throw new IllegalArgumentException("ECIES public key is required for encryption");
        }

        byte[] aesKey = new byte[AES_KEY_BYTES];
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(aesKey);
        random.nextBytes(iv);

        byte[] encKey = encryptKey(aesKey, material.publicKey);

        DataOutputStream dataOut = new DataOutputStream(output);
        dataOut.writeByte(VERSION);
        dataOut.writeShort(encKey.length);
        dataOut.write(encKey);
        dataOut.writeByte(iv.length);
        dataOut.write(iv);
        dataOut.flush();

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        try (CipherOutputStream cipherOut = new CipherOutputStream(output, cipher)) {
            input.transferTo(cipherOut);
        }
    }

    @Override
    public void decrypt(java.io.InputStream input, java.io.OutputStream output, String key) throws Exception {
        KeyMaterial material = resolveKeyMaterial(key);
        if (material.privateKey == null) {
            throw new IllegalArgumentException("ECIES private key is required for decryption");
        }

        DataInputStream in = new DataInputStream(input);
        int version = in.readUnsignedByte();
        if (version != VERSION) {
            throw new IllegalArgumentException("Unsupported ECIES payload version: " + version);
        }
        int encKeyLen = in.readUnsignedShort();
        if (encKeyLen <= 0) {
            throw new IllegalArgumentException("Invalid encrypted key length: " + encKeyLen);
        }
        byte[] encKey = new byte[encKeyLen];
        in.readFully(encKey);
        int ivLen = in.readUnsignedByte();
        if (ivLen <= 0 || ivLen > 32) {
            throw new IllegalArgumentException("Invalid IV length: " + ivLen);
        }
        byte[] iv = new byte[ivLen];
        in.readFully(iv);

        byte[] aesKey = decryptKey(encKey, material.privateKey);
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        try (CipherInputStream cipherIn = new CipherInputStream(in, cipher)) {
            cipherIn.transferTo(output);
        }
    }

    @Override
    public String getAlgorithmName() {
        return "ECIES-HYBRID";
    }

    public String getPublicKeyBase64() {
        if (keyPair == null) {
            return "";
        }
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public String getPrivateKeyBase64() {
        if (keyPair == null) {
            return "";
        }
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }

    private byte[] encryptKey(byte[] key, PublicKey publicKey) throws Exception {
        BouncyCastleSupport.ensureProvider();
        Cipher cipher = Cipher.getInstance(ECIES_CIPHER, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, new SecureRandom());
        return cipher.doFinal(key);
    }

    private byte[] decryptKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        BouncyCastleSupport.ensureProvider();
        Cipher cipher = Cipher.getInstance(ECIES_CIPHER, "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKey);
    }

    private KeyMaterial resolveKeyMaterial(String key) throws Exception {
        if (key != null && !key.trim().isEmpty()) {
            return parseKeyMaterial(key.trim());
        }
        if (keyPair == null) {
            generateKeyPair();
        }
        return new KeyMaterial(keyPair.getPublic(), keyPair.getPrivate());
    }

    private KeyMaterial parseKeyMaterial(String key) throws Exception {
        KeyMaterial material = new KeyMaterial(null, null);
        String[] parts = key.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (trimmed.startsWith("pub:")) {
                material.publicKey = decodePublicKey(trimmed.substring(4));
            } else if (trimmed.startsWith("priv:")) {
                material.privateKey = decodePrivateKey(trimmed.substring(5));
            } else {
                if (material.publicKey == null) {
                    try {
                        material.publicKey = decodePublicKey(trimmed);
                        continue;
                    } catch (Exception ignore) {
                    }
                }
                if (material.privateKey == null) {
                    material.privateKey = decodePrivateKey(trimmed);
                }
            }
        }
        return material;
    }

    private PublicKey decodePublicKey(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance(EC_ALGORITHM, "BC");
        return factory.generatePublic(spec);
    }

    private PrivateKey decodePrivateKey(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance(EC_ALGORITHM, "BC");
        return factory.generatePrivate(spec);
    }

    private static final class KeyMaterial {
        private PublicKey publicKey;
        private PrivateKey privateKey;

        private KeyMaterial(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
    }
}
