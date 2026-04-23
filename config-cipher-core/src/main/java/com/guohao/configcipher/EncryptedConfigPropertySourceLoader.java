package com.guohao.configcipher;

import org.springframework.boot.env.PropertiesPropertySourceLoader;
import org.springframework.boot.env.PropertySourceLoader;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;

public class EncryptedConfigPropertySourceLoader implements PropertySourceLoader {
    private final PropertySourceLoader yamlLoader = new YamlPropertySourceLoader();
    private final PropertySourceLoader propertiesLoader = new PropertiesPropertySourceLoader();

    @Override
    public String[] getFileExtensions() {
        return new String[] { "enc", "yml.enc", "yaml.enc", "properties.enc" };
    }

    @Override
    public List<PropertySource<?>> load(String name, Resource resource) throws IOException {
        if (resource == null || !resource.exists()) {
            return Collections.emptyList();
        }

        String filename = resource.getFilename();
        if (filename == null) {
            return Collections.emptyList();
        }

        String innerName = stripEncExtension(filename);
        PropertySourceLoader delegate = selectLoader(innerName);
        KeyRing keyRing = KeyRing.fromEnvironment();

        byte[] decrypted;
        try (InputStream in = resource.getInputStream()) {
            decrypted = EncryptedConfigIO.decryptToBytes(in, keyRing);
        } catch (GeneralSecurityException ex) {
            throw new IOException("Failed to decrypt config: " + filename, ex);
        }

        ByteArrayResource decryptedResource = new ByteArrayResource(decrypted) {
            @Override
            public String getFilename() {
                return innerName;
            }
        };

        return delegate.load(name, decryptedResource);
    }

    private PropertySourceLoader selectLoader(String filename) {
        String lower = filename.toLowerCase();
        if (lower.endsWith(".yml") || lower.endsWith(".yaml")) {
            return yamlLoader;
        }
        return propertiesLoader;
    }

    private static String stripEncExtension(String filename) {
        if (filename.toLowerCase().endsWith(".enc")) {
            return filename.substring(0, filename.length() - 4);
        }
        return filename;
    }
}
