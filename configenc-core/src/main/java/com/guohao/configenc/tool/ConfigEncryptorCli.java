package com.guohao.configenc.tool;

import com.guohao.EncryptionFactory;
import com.guohao.configenc.EncryptedConfigIO;
import com.guohao.configenc.KeyRing;

import java.nio.file.Path;
import java.util.Locale;

public final class ConfigEncryptorCli {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            return;
        }

        String action = args[0];
        if ("encrypt".equalsIgnoreCase(action)) {
            if (args.length < 4) {
                printUsage();
                return;
            }
            EncryptionFactory.AlgorithmType algorithmType = parseAlgorithm(args[1]);
            Path input = Path.of(args[2]);
            Path output = Path.of(args[3]);
            String keyId = args.length >= 5 ? args[4] : null;
            String explicitKey = args.length >= 6 ? args[5] : null;
            KeyRing keyRing = explicitKey == null ? KeyRing.fromEnvironment() : null;
            if (explicitKey != null && (keyId == null || keyId.isBlank())) {
                keyId = "default";
            }
            EncryptedConfigIO.encryptFile(input, output, algorithmType, keyRing, keyId, explicitKey);
            System.out.println("Encrypted: " + input + " -> " + output);
            return;
        }

        if ("decrypt".equalsIgnoreCase(action)) {
            if (args.length < 3) {
                printUsage();
                return;
            }
            Path input = Path.of(args[1]);
            Path output = Path.of(args[2]);
            KeyRing keyRing = KeyRing.fromEnvironment();
            EncryptedConfigIO.decryptFile(input, output, keyRing);
            System.out.println("Decrypted: " + input + " -> " + output);
            return;
        }

        printUsage();
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  encrypt <algorithm> <input> <output> [keyId] [key]");
        System.out.println("  decrypt <input> <output>");
        System.out.println();
        System.out.println("Algorithms:");
        System.out.println("  AES | SM4 | RSA | SM2 | ECIES");
        System.out.println();
        System.out.println("Environment:");
        System.out.println("  CONFIG_ENC_KEYRING=key1:BASE64,key2:BASE64");
        System.out.println("  CONFIG_ENC_ACTIVE_KEY_ID=key1");
    }

    private static EncryptionFactory.AlgorithmType parseAlgorithm(String value) {
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return EncryptionFactory.AlgorithmType.valueOf(normalized);
    }
}
