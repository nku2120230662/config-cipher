package com.guohao.configenc;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class KeyRing {
    public static final String ENV_KEYRING = "CONFIG_ENC_KEYRING";
    public static final String ENV_ACTIVE_KEY_ID = "CONFIG_ENC_ACTIVE_KEY_ID";
    public static final String ENV_SINGLE_KEY = "CONFIG_ENC_KEY";
    public static final String ENV_SINGLE_KEY_ID = "CONFIG_ENC_KEY_ID";

    private final Map<String, String> keys;
    private final String activeKeyId;

    private KeyRing(Map<String, String> keys, String activeKeyId) {
        this.keys = Collections.unmodifiableMap(new LinkedHashMap<>(keys));
        this.activeKeyId = activeKeyId;
    }

    public static KeyRing fromEnvironment() {
        Map<String, String> parsed = parseKeyRing(System.getenv(ENV_KEYRING));
        if (parsed.isEmpty()) {
            String singleKey = trimToNull(System.getenv(ENV_SINGLE_KEY));
            if (singleKey != null) {
                String keyId = trimToNull(System.getenv(ENV_SINGLE_KEY_ID));
                if (keyId == null) {
                    keyId = "default";
                }
                parsed.put(keyId, singleKey);
            }
        }

        if (parsed.isEmpty()) {
            throw new IllegalStateException("No encryption keys found in environment. Set " + ENV_KEYRING + " or " + ENV_SINGLE_KEY + ".");
        }

        String active = trimToNull(System.getenv(ENV_ACTIVE_KEY_ID));
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

    private static Map<String, String> parseKeyRing(String raw) {
        String value = trimToNull(raw);
        if (value == null) {
            return new LinkedHashMap<>();
        }

        Map<String, String> result = new LinkedHashMap<>();
        String[] entries = value.split("[;,]");
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

}
