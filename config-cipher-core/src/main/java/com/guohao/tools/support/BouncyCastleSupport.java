package com.guohao.tools.support;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public final class BouncyCastleSupport {
    private static volatile boolean installed = false;

    private BouncyCastleSupport() {
    }

    public static void ensureProvider() {
        if (!installed) {
            synchronized (BouncyCastleSupport.class) {
                if (!installed) {
                    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                        Security.addProvider(new BouncyCastleProvider());
                    }
                    installed = true;
                }
            }
        }
    }
}
