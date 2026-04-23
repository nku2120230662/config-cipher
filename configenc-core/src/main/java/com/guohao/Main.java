package com.guohao;// 6. 主程序和演示

import java.util.Scanner;

public class Main {
    public static void main(String[] args)throws Exception {
        Scanner scanner = new Scanner(System.in);
        FileEncryptionService service;

        try {
            System.out.println("=== 文件加密系统 ===");
            System.out.println("支持的加密算法:");
            System.out.println("1. AES-GCM");
            System.out.println("2. SM4-GCM");
            System.out.println("3. RSA (混合加密: RSA + AES-GCM)");
            System.out.println("4. SM2 (混合加密: SM2 + SM4-GCM)");
            System.out.println("5. ECIES (混合加密: ECIES + AES-GCM)");

            System.out.print("请选择加密算法 (1-5): ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // 消费换行符

            EncryptionAlgorithm algorithm = null;
            switch (choice) {
                case 1:
                    algorithm = EncryptionFactory.createAlgorithm(
                            EncryptionFactory.AlgorithmType.AES);
                    break;
                case 2:
                    algorithm = EncryptionFactory.createAlgorithm(
                            EncryptionFactory.AlgorithmType.SM4);
                    break;
                case 3:
                    algorithm = EncryptionFactory.createAlgorithm(
                            EncryptionFactory.AlgorithmType.RSA);
                    break;
                case 4:
                    algorithm = EncryptionFactory.createAlgorithm(
                            EncryptionFactory.AlgorithmType.SM2);
                    break;
                case 5:
                    algorithm = EncryptionFactory.createAlgorithm(
                            EncryptionFactory.AlgorithmType.ECIES);
                    break;
                default:
                    System.out.println("无效选择!");
                    return;
            }

            service = new FileEncryptionServiceImpl(algorithm);

            System.out.print("请选择操作 (1-加密, 2-解密): ");
            int operation = scanner.nextInt();
            scanner.nextLine();

            System.out.print("请输入源文件路径: ");
            String inputFile = scanner.nextLine();

            System.out.print("请输入目标文件路径: ");
            String outputFile = scanner.nextLine();

            String key = "";
            if (choice == 1 || choice == 2) { // 对称算法
                System.out.print("请输入Base64密钥: ");
                key = scanner.nextLine();
            } else if (choice >= 3) { // 混合加密
                if (operation == 1) {
                    System.out.print("请输入公钥(Base64)，格式: pub:BASE64 或直接Base64: ");
                } else {
                    System.out.print("请输入私钥(Base64)，格式: priv:BASE64 或直接Base64: ");
                }
                key = scanner.nextLine();
            }

            if (operation == 1) {
                service.encryptFile(inputFile, outputFile, key);
            } else if (operation == 2) {
                service.decryptFile(inputFile, outputFile, key);
            } else {
                System.out.println("无效操作!");
            }

        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }

    // 演示方法
    public static void demonstrateAllAlgorithms() {
        try {
            String testData = "这是一个测试文件内容，用于演示各种加密算法。";
            byte[] data = testData.getBytes("UTF-8");
            String key = com.guohao.tools.sys.AESEncryption.generateKeyBase64();

            System.out.println("=== 加密算法演示 ===");
            System.out.println("原始数据: " + testData);
            System.out.println();

            // 测试所有算法
            EncryptionFactory.AlgorithmType[] algorithms =
                    EncryptionFactory.AlgorithmType.values();

            for (EncryptionFactory.AlgorithmType algType : algorithms) {
                try {
                    EncryptionAlgorithm alg = EncryptionFactory.createAlgorithm(algType);

                    String algKey = key;
                    if (alg instanceof com.guohao.tools.ays.RSAEncryption rsa) {
                        String pub = rsa.getPublicKeyBase64();
                        String priv = rsa.getPrivateKeyBase64();
                        algKey = "pub:" + pub + ";priv:" + priv;
                    } else if (alg instanceof com.guohao.tools.ays.SM2Encryption sm2) {
                        String pub = sm2.getPublicKeyBase64();
                        String priv = sm2.getPrivateKeyBase64();
                        algKey = "pub:" + pub + ";priv:" + priv;
                    } else if (alg instanceof com.guohao.tools.ays.ECIESEncryption ecies) {
                        String pub = ecies.getPublicKeyBase64();
                        String priv = ecies.getPrivateKeyBase64();
                        algKey = "pub:" + pub + ";priv:" + priv;
                    }

                    byte[] encrypted = alg.encrypt(data, algKey);
                    byte[] decrypted = alg.decrypt(encrypted, algKey);

                    System.out.println("算法: " + alg.getAlgorithmName());
                    System.out.println("加密后长度: " + encrypted.length + " 字节");
                    System.out.println("解密结果: " + new String(decrypted, "UTF-8"));
                    System.out.println("解密成功: " + testData.equals(new String(decrypted, "UTF-8")));
                    System.out.println("---");

                } catch (Exception e) {
                    System.out.println("算法 " + algType + " 测试失败: " + e.getMessage());
                    System.out.println("---");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
