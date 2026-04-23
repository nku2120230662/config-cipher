package com.guohao;

// 文件加密服务

public interface FileEncryptionService {
    void encryptFile(String inputFilePath, String outputFilePath, String key) throws Exception;
    void decryptFile(String inputFilePath, String outputFilePath, String key) throws Exception;
}
