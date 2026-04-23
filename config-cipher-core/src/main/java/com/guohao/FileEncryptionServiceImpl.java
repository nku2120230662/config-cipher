package com.guohao;

import java.nio.file.Files;
import java.nio.file.Paths;

public class FileEncryptionServiceImpl implements FileEncryptionService {
    private EncryptionAlgorithm algorithm;

    public FileEncryptionServiceImpl(EncryptionAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public void encryptFile(String inputFilePath, String outputFilePath, String key) throws Exception {
        try (var in = Files.newInputStream(Paths.get(inputFilePath));
             var out = Files.newOutputStream(Paths.get(outputFilePath))) {
            algorithm.encrypt(in, out, key);
        }

        System.out.println("文件加密完成:");
        System.out.println("算法: " + algorithm.getAlgorithmName());
        System.out.println("输入文件: " + inputFilePath);
        System.out.println("输出文件: " + outputFilePath);
    }

    @Override
    public void decryptFile(String inputFilePath, String outputFilePath, String key) throws Exception {
        try (var in = Files.newInputStream(Paths.get(inputFilePath));
             var out = Files.newOutputStream(Paths.get(outputFilePath))) {
            algorithm.decrypt(in, out, key);
        }

        System.out.println("文件解密完成:");
        System.out.println("算法: " + algorithm.getAlgorithmName());
        System.out.println("输入文件: " + inputFilePath);
        System.out.println("输出文件: " + outputFilePath);
    }

    public void setAlgorithm(EncryptionAlgorithm algorithm) {
        this.algorithm = algorithm;
    }
}
