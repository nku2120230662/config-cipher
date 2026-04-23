package com.guohao.configcipher;

import com.guohao.EncryptionAlgorithm;
import com.guohao.EncryptionFactory;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Locale;

public final class EncryptedConfigIO {
    private static final byte[] MAGIC = new byte[] { 'C', 'F', 'E', 'C' };
    private static final int VERSION_V1 = 1;
    private static final int VERSION_V2 = 2;
    private static final int ALG_AES_GCM = 1;
    private static final int GCM_TAG_BITS = 128;

    private EncryptedConfigIO() {
    }

    public static void encryptFile(Path input,
                                   Path output,
                                   EncryptionFactory.AlgorithmType algorithmType,
                                   KeyRing keyRing,
                                   String keyId,
                                   String explicitKey)
            throws IOException, GeneralSecurityException {
        String resolvedKeyId = keyId == null && keyRing != null ? keyRing.getActiveKeyId() : keyId;
        String key = explicitKey;
        if (key == null && keyRing != null) {
            key = keyRing.getKey(resolvedKeyId);
        }
        if (key == null) {
            throw new IllegalArgumentException("Key not found for encryption.");
        }
        try (InputStream in = Files.newInputStream(input);
             OutputStream out = Files.newOutputStream(output)) {
            encrypt(in, out, algorithmType, key, resolvedKeyId);
        }
    }

    public static void decryptFile(Path input, Path output, KeyRing keyRing)
            throws IOException, GeneralSecurityException {
        try (InputStream in = Files.newInputStream(input);
             OutputStream out = Files.newOutputStream(output)) {
            decrypt(in, out, keyRing);
        }
    }

    public static void encrypt(InputStream plaintext,
                               OutputStream encrypted,
                               EncryptionFactory.AlgorithmType algorithmType,
                               String key,
                               String keyId)
            throws IOException, GeneralSecurityException {
        EncryptionAlgorithm algorithm;
        try {
            algorithm = EncryptionFactory.createAlgorithm(algorithmType);
        } catch (Exception ex) {
            throw new GeneralSecurityException("Algorithm encryption failed: " + algorithmType, ex);
        }
        writeHeader(encrypted, algorithmType.name(), keyId);
        try {
            algorithm.encrypt(plaintext, encrypted, key);
        } catch (Exception ex) {
            throw new GeneralSecurityException("Algorithm encryption failed: " + algorithmType, ex);
        }
    }

    public static void decrypt(InputStream encrypted, OutputStream plaintext, KeyRing keyRing)
            throws IOException, GeneralSecurityException {
        DataInputStream dataIn = new DataInputStream(encrypted);
        Header header = readHeader(dataIn);

        if (header.version == VERSION_V1) {
            String key = resolveKey(keyRing, header.keyId);
            if (key == null) {
                throw new IllegalStateException("Key id not found: " + header.keyId + ". Available: " + keyRing.getKeyIds());
            }
            decryptBodyV1(dataIn, plaintext, key, header.iv);
            return;
        }

        EncryptionFactory.AlgorithmType algorithmType = parseAlgorithm(header.algorithmId);
        EncryptionAlgorithm algorithm;
        try {
            algorithm = EncryptionFactory.createAlgorithm(algorithmType);
        } catch (Exception ex) {
            throw new GeneralSecurityException("Algorithm creation failed: " + algorithmType, ex);
        }
        String key = resolveKey(keyRing, header.keyId);
        if (key == null) {
            throw new IllegalStateException("Key id not found: " + header.keyId + ". Available: " + keyRing.getKeyIds());
        }
        try {
            algorithm.decrypt(dataIn, plaintext, key);
        } catch (Exception ex) {
            throw new GeneralSecurityException("Algorithm decryption failed: " + algorithmType, ex);
        }
    }

    public static byte[] decryptToBytes(InputStream encrypted, KeyRing keyRing)
            throws IOException, GeneralSecurityException {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            decrypt(encrypted, out, keyRing);
            return out.toByteArray();
        }
    }

    private static void decryptBodyV1(InputStream encrypted, OutputStream plaintext, String key, byte[] iv)
            throws IOException, GeneralSecurityException {
        SecretKeySpec secretKey = new SecretKeySpec(normalizeAesKey(decodeKey(key)), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        try (CipherInputStream cipherIn = new CipherInputStream(encrypted, cipher)) {
            cipherIn.transferTo(plaintext);
        }
    }

    private static void writeHeader(OutputStream out, String algorithmId, String keyId) throws IOException {
        byte[] algBytes = algorithmId == null ? new byte[0] : algorithmId.getBytes(StandardCharsets.UTF_8);
        byte[] keyIdBytes = keyId == null ? new byte[0] : keyId.getBytes(StandardCharsets.UTF_8);
        if (algBytes.length == 0) {
            throw new IllegalArgumentException("Algorithm id is required.");
        }
        if (algBytes.length > 255) {
            throw new IllegalArgumentException("Algorithm id too long: " + algBytes.length);
        }
        if (keyIdBytes.length > 255) {
            throw new IllegalArgumentException("Key id too long: " + keyIdBytes.length);
        }

        DataOutputStream dataOut = new DataOutputStream(out);
        dataOut.write(MAGIC);
        dataOut.writeByte(VERSION_V2);
        dataOut.writeByte(algBytes.length);
        dataOut.write(algBytes);
        dataOut.writeByte(keyIdBytes.length);
        dataOut.write(keyIdBytes);
        dataOut.flush();
    }

    private static Header readHeader(DataInputStream in) throws IOException {
        byte[] magic = new byte[MAGIC.length];
        in.readFully(magic);
        if (!Arrays.equals(MAGIC, magic)) {
            throw new IOException("Invalid file magic. Not an encrypted config file.");
        }
        int version = in.readUnsignedByte();
        if (version == VERSION_V1) {
            int alg = in.readUnsignedByte();
            if (alg != ALG_AES_GCM) {
                throw new IOException("Unsupported algorithm id: " + alg);
            }
            int keyIdLen = in.readUnsignedByte();
            byte[] keyIdBytes = new byte[keyIdLen];
            if (keyIdLen > 0) {
                in.readFully(keyIdBytes);
            }
            int ivLen = in.readUnsignedByte();
            if (ivLen <= 0 || ivLen > 32) {
                throw new IOException("Invalid IV length: " + ivLen);
            }
            byte[] iv = new byte[ivLen];
            in.readFully(iv);
            String keyId = new String(keyIdBytes, StandardCharsets.UTF_8);
            return new Header(version, "", keyId, iv);
        }
        if (version != VERSION_V2) {
            throw new IOException("Unsupported encrypted config version: " + version);
        }
        int algLen = in.readUnsignedByte();
        if (algLen <= 0) {
            throw new IOException("Algorithm id missing.");
        }
        byte[] algBytes = new byte[algLen];
        in.readFully(algBytes);
        int keyIdLen = in.readUnsignedByte();
        byte[] keyIdBytes = new byte[keyIdLen];
        if (keyIdLen > 0) {
            in.readFully(keyIdBytes);
        }
        String algId = new String(algBytes, StandardCharsets.UTF_8);
        String keyId = new String(keyIdBytes, StandardCharsets.UTF_8);
        return new Header(version, algId, keyId, new byte[0]);
    }

    private static final class Header {
        private final int version;
        private final String algorithmId;
        private final String keyId;
        private final byte[] iv;

        private Header(int version, String algorithmId, String keyId, byte[] iv) {
            this.version = version;
            this.algorithmId = algorithmId == null ? "" : algorithmId;
            this.keyId = keyId == null ? "" : keyId;
            this.iv = iv;
        }
    }

    private static String resolveKey(KeyRing keyRing, String keyId) {
        if (keyRing == null) {
            return null;
        }
        if (keyId == null || keyId.isEmpty()) {
            return keyRing.getActiveKey();
        }
        String key = keyRing.getKey(keyId);
        if (key == null) {
            return keyRing.getActiveKey();
        }
        return key;
    }

    private static EncryptionFactory.AlgorithmType parseAlgorithm(String value) {
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return EncryptionFactory.AlgorithmType.valueOf(normalized);
    }

    private static byte[] decodeKey(String key) {
        if (key == null || key.trim().isEmpty()) {
            throw new IllegalArgumentException("AES key is required");
        }
        try {
            return java.util.Base64.getDecoder().decode(key.trim().getBytes(StandardCharsets.US_ASCII));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("AES key must be valid Base64.", ex);
        }
    }

    private static byte[] normalizeAesKey(byte[] rawKey) {
        int len = rawKey.length;
        if (len != 16 && len != 24 && len != 32) {
            throw new IllegalArgumentException(
                    "AES key must decode to 16, 24, or 32 bytes, got " + len + ".");
        }
        return rawKey;
    }
}
