package com.guohao.configenc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class KeyRing {
    public static final String ENV_KEYRING = "CONFIG_ENC_KEYRING";
    public static final String ENV_ACTIVE_KEY_ID = "CONFIG_ENC_ACTIVE_KEY_ID";
    public static final String ENV_SINGLE_KEY = "CONFIG_ENC_KEY";
    public static final String ENV_SINGLE_KEY_ID = "CONFIG_ENC_KEY_ID";
    public static final String ENV_KEY_FILE = "CONFIG_ENC_KEY_FILE";
    public static final String ENV_KEYRING_FILE = "CONFIG_ENC_KEYRING_FILE";

    public static final String SYS_KEYRING = "config.enc.keyring";
    public static final String SYS_ACTIVE_KEY_ID = "config.enc.active.key.id";
    public static final String SYS_SINGLE_KEY = "config.enc.key";
    public static final String SYS_SINGLE_KEY_ID = "config.enc.key.id";
    public static final String SYS_KEY_FILE = "config.enc.key.file";
    public static final String SYS_KEYRING_FILE = "config.enc.keyring.file";

    private final Map<String, String> keys;
    private final String activeKeyId;

    private KeyRing(Map<String, String> keys, String activeKeyId) {
        this.keys = Collections.unmodifiableMap(new LinkedHashMap<>(keys));
        this.activeKeyId = activeKeyId;
    }

    public static KeyRing fromEnvironment() {
        Map<String, String> parsed = loadKeyRing();
        if (parsed.isEmpty()) {
            loadSingleKeyInto(parsed);
        }

        if (parsed.isEmpty()) {
            throw new IllegalStateException(noKeyDiagnostic());
        }

        String active = resolve(SYS_ACTIVE_KEY_ID, ENV_ACTIVE_KEY_ID);
        if (active == null) {
            active = parsed.keySet().iterator().next();
        }

        if (!parsed.containsKey(active)) {
            throw new IllegalStateException("Active key id not found: " + active + ". Available: " + parsed.keySet());
        }

        return new KeyRing(parsed, active);
    }

    public String getActiveKey() {
        return keys.get(activeKeyId);
    }

    public String getActiveKeyId() {
        return activeKeyId;
    }

    public String getKey(String keyId) {
        if (keyId == null) {
            return null;
        }
        return keys.get(keyId);
    }

    public Set<String> getKeyIds() {
        return keys.keySet();
    }

    private static Map<String, String> loadKeyRing() {
        String inline = resolve(SYS_KEYRING, ENV_KEYRING);
        if (inline != null) {
            return parseKeyRing(inline);
        }
        String filePath = resolve(SYS_KEYRING_FILE, ENV_KEYRING_FILE);
        if (filePath != null) {
            return parseKeyRing(readKeyFile(filePath, "keyring"));
        }
        return new LinkedHashMap<>();
    }

    private static void loadSingleKeyInto(Map<String, String> target) {
        String key = resolve(SYS_SINGLE_KEY, ENV_SINGLE_KEY);
        if (key == null) {
            String filePath = resolve(SYS_KEY_FILE, ENV_KEY_FILE);
            if (filePath != null) {
                key = trimToNull(readKeyFile(filePath, "key"));
            }
        }
        if (key == null) {
            return;
        }
        String keyId = resolve(SYS_SINGLE_KEY_ID, ENV_SINGLE_KEY_ID);
        if (keyId == null) {
            keyId = "default";
        }
        target.put(keyId, key);
    }

    private static String resolve(String systemProperty, String environmentVariable) {
        String sys = trimToNull(System.getProperty(systemProperty));
        if (sys != null) {
            return sys;
        }
        return trimToNull(System.getenv(environmentVariable));
    }

    private static String readKeyFile(String path, String what) {
        Path p = Path.of(path);
        if (!Files.isRegularFile(p)) {
            throw new IllegalStateException("Configured " + what + " file does not exist: " + path);
        }
        try {
            return Files.readString(p);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to read " + what + " file: " + path + " (" + ex.getMessage() + ")", ex);
        }
    }

    private static Map<String, String> parseKeyRing(String raw) {
        String value = trimToNull(raw);
        if (value == null) {
            return new LinkedHashMap<>();
        }

        Map<String, String> result = new LinkedHashMap<>();
        String[] entries = value.split("[;,\\r\\n]");
        for (String entry : entries) {
            String trimmed = trimToNull(entry);
            if (trimmed == null) {
                continue;
            }
            String[] parts = trimmed.split("[:=]", 2);
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid key ring entry: " + trimmed);
            }
            String id = trimToNull(parts[0]);
            String keyBase64 = trimToNull(parts[1]);
            if (id == null || keyBase64 == null) {
                throw new IllegalArgumentException("Invalid key ring entry: " + trimmed);
            }
            if (result.containsKey(id)) {
                throw new IllegalArgumentException("Duplicate key id: " + id);
            }
            result.put(id, keyBase64);
        }
        return result;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String noKeyDiagnostic() {
        return "No decryption key found. Provide a key through one of:\n"
                + "  -D" + SYS_KEYRING + "=keyId:BASE64[,keyId2:BASE64]\n"
                + "  -D" + SYS_SINGLE_KEY + "=BASE64          (optional -D" + SYS_SINGLE_KEY_ID + "=default)\n"
                + "  -D" + SYS_KEYRING_FILE + "=/path/to/keyring\n"
                + "  -D" + SYS_KEY_FILE + "=/path/to/single-key-file\n"
                + "  " + ENV_KEYRING + "=keyId:BASE64[,keyId2:BASE64]\n"
                + "  " + ENV_SINGLE_KEY + "=BASE64          (optional " + ENV_SINGLE_KEY_ID + "=default)\n"
                + "  " + ENV_KEYRING_FILE + "=/path/to/keyring\n"
                + "  " + ENV_KEY_FILE + "=/path/to/single-key-file";
    }
}
