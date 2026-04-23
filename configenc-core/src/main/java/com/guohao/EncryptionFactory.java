package com.guohao;

import com.guohao.tools.ays.ECIESEncryption;
import com.guohao.tools.ays.RSAEncryption;
import com.guohao.tools.ays.SM2Encryption;
import com.guohao.tools.sys.AESEncryption;
import com.guohao.tools.sys.SM4Encryption;

// 加密算法工厂
public class EncryptionFactory {
    public enum AlgorithmType {
        AES, SM4, RSA, SM2, ECIES,
    }

    public static EncryptionAlgorithm createAlgorithm(AlgorithmType type) throws Exception {
        switch (type) {
            case AES:
                return new AESEncryption();
            case SM4:
                return new SM4Encryption();
            case RSA:
                return new RSAEncryption();
            case SM2:
                return new SM2Encryption();
            case ECIES:
                return new ECIESEncryption();
            default:
                throw new IllegalArgumentException("不支持的加密算法类型");
        }
    }
}
