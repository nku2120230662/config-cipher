package com.guohao.tools.ays;

import com.guohao.EncryptionAlgorithm;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

// RSA + AES-GCM 混合加密实现
public class RSAEncryption implements EncryptionAlgorithm {
    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int VERSION_V1 = 1;
    private static final int VERSION_V2 = 2;
    private static final int AES_KEY_BYTES = 32;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private KeyPair keyPair;

    public RSAEncryption() throws Exception {
        generateKeyPair();
    }

    private void generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(2048);
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
            throw new IllegalArgumentException("RSA public key is required for encryption");
        }

        byte[] aesKey = new byte[AES_KEY_BYTES];
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(aesKey);
        random.nextBytes(iv);

        byte[] encKey = encryptKey(aesKey, material.publicKey);

        DataOutputStream dataOut = new DataOutputStream(output);
        dataOut.writeByte(VERSION_V2);
        dataOut.writeShort(encKey.length);
        dataOut.write(encKey);
        dataOut.writeByte(iv.length);
        dataOut.write(iv);
        dataOut.flush();

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(buildAad(VERSION_V2, encKey, iv));
        try (CipherOutputStream cipherOut = new CipherOutputStream(output, cipher)) {
            input.transferTo(cipherOut);
        }
    }

    @Override
    public void decrypt(java.io.InputStream input, java.io.OutputStream output, String key) throws Exception {
        KeyMaterial material = resolveKeyMaterial(key);
        if (material.privateKey == null) {
            throw new IllegalArgumentException("RSA private key is required for decryption");
        }

        DataInputStream in = new DataInputStream(input);
        int version = in.readUnsignedByte();
        if (version != VERSION_V1 && version != VERSION_V2) {
            throw new IllegalArgumentException("Unsupported RSA payload version: " + version);
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
        if (version == VERSION_V2) {
            cipher.updateAAD(buildAad(version, encKey, iv));
        }
        try (CipherInputStream cipherIn = new CipherInputStream(in, cipher)) {
            cipherIn.transferTo(output);
        }
    }

    private static byte[] buildAad(int version, byte[] encKey, byte[] iv) {
        ByteBuffer buf = ByteBuffer.allocate(1 + 2 + encKey.length + 1 + iv.length);
        buf.put((byte) version);
        buf.putShort((short) encKey.length);
        buf.put(encKey);
        buf.put((byte) iv.length);
        buf.put(iv);
        return buf.array();
    }

    @Override
    public String getAlgorithmName() {
        return "RSA-HYBRID";
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
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(key);
    }

    private byte[] decryptKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKey);
    }

    private KeyMaterial resolveKeyMaterial(String key) throws Exception {
        if (key == null || key.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "RSA key material is required. Provide 'pub:BASE64' and/or 'priv:BASE64' (separated by ';').");
        }
        return parseKeyMaterial(key.trim());
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
            } else if (material.publicKey == null) {
                Exception pubEx;
                try {
                    material.publicKey = decodePublicKey(trimmed);
                    continue;
                } catch (Exception ex) {
                    pubEx = ex;
                }
                try {
                    material.privateKey = decodePrivateKey(trimmed);
                } catch (Exception privEx) {
                    throw new IllegalArgumentException(
                            "Unable to parse RSA key. Use 'pub:BASE64' or 'priv:BASE64'. "
                                    + "Tried as public key (" + pubEx.getMessage()
                                    + ") then as private key (" + privEx.getMessage() + ").");
                }
            } else if (material.privateKey == null) {
                material.privateKey = decodePrivateKey(trimmed);
            }
        }
        return material;
    }

    private PublicKey decodePublicKey(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance(RSA_ALGORITHM);
        return factory.generatePublic(spec);
    }

    private PrivateKey decodePrivateKey(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance(RSA_ALGORITHM);
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
