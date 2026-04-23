import com.guohao.EncryptionAlgorithm;
import com.guohao.EncryptionFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.DecimalFormat;
import java.util.*;

// 性能测试结果类
class PerformanceResult {
    private String algorithmName;
    private long originalSize;
    private long encryptedSize;
    private long encryptionTime;
    private long decryptionTime;
    private boolean successful;
    private String errorMessage;

    public PerformanceResult(String algorithmName) {
        this.algorithmName = algorithmName;
        this.successful = true;
    }

    // Getters and Setters
    public String getAlgorithmName() { return algorithmName; }
    public long getOriginalSize() { return originalSize; }
    public void setOriginalSize(long originalSize) { this.originalSize = originalSize; }
    public long getEncryptedSize() { return encryptedSize; }
    public void setEncryptedSize(long encryptedSize) { this.encryptedSize = encryptedSize; }
    public long getEncryptionTime() { return encryptionTime; }
    public void setEncryptionTime(long encryptionTime) { this.encryptionTime = encryptionTime; }
    public long getDecryptionTime() { return decryptionTime; }
    public void setDecryptionTime(long decryptionTime) { this.decryptionTime = decryptionTime; }
    public boolean isSuccessful() { return successful; }
    public void setSuccessful(boolean successful) { this.successful = successful; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public double getSizeRatio() {
        return originalSize > 0 ? (double) encryptedSize / originalSize : 0;
    }

    public double getEncryptionSpeed() {
        return encryptionTime > 0 ? (double) originalSize / encryptionTime * 1000 : 0; // bytes/sec
    }

    public double getDecryptionSpeed() {
        return decryptionTime > 0 ? (double) encryptedSize / decryptionTime * 1000 : 0; // bytes/sec
    }
}

// 测试数据生成器
class TestDataGenerator {
    private static final Random random = new Random();

    public static byte[] generateRandomData(int size) {
        byte[] data = new byte[size];
        random.nextBytes(data);
        return data;
    }

    public static byte[] generateTextData(int size) {
        StringBuilder sb = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \n";

        while (sb.length() < size) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }

        return sb.toString().substring(0, size).getBytes();
    }

    public static byte[] generateRepeatingData(int size) {
        byte[] pattern = "Hello World! This is a test pattern. ".getBytes();
        byte[] data = new byte[size];

        for (int i = 0; i < size; i++) {
            data[i] = pattern[i % pattern.length];
        }

        return data;
    }

    public static void createTestFiles() throws IOException {
        // 创建不同大小的测试文件
        int[] sizes = {1024, 10240, 102400, 1048576}; // 1KB, 10KB, 100KB, 1MB
        String[] types = {"random", "text", "repeating"};

        for (int size : sizes) {
            for (String type : types) {
                String fileName = String.format("test_%s_%dKB.dat", type, size / 1024);
                byte[] data;

                switch (type) {
                    case "random":
                        data = generateRandomData(size);
                        break;
                    case "text":
                        data = generateTextData(size);
                        break;
                    case "repeating":
                        data = generateRepeatingData(size);
                        break;
                    default:
                        continue;
                }

                Files.write(Paths.get(fileName), data);
                System.out.println("创建测试文件: " + fileName + " (" + size + " 字节)");
            }
        }
    }
}

// 性能测试器
class EncryptionPerformanceTester {
    private List<PerformanceResult> results;
    private DecimalFormat df = new DecimalFormat("#,##0.00");
    private DecimalFormat speedFormat = new DecimalFormat("#,##0");

    public EncryptionPerformanceTester() {
        results = new ArrayList<>();
    }

    public void testAlgorithm(EncryptionAlgorithm algorithm, byte[] testData, String key) {
        PerformanceResult result = new PerformanceResult(algorithm.getAlgorithmName());
        result.setOriginalSize(testData.length);

        try {
            // 预热JVM
            for (int i = 0; i < 3; i++) {
                algorithm.encrypt(testData, key);
            }

            // 测试加密性能
            long startTime = System.currentTimeMillis();
            byte[] encryptedData = algorithm.encrypt(testData, key);
            long encryptionTime = System.currentTimeMillis() - startTime;

            result.setEncryptedSize(encryptedData.length);
            result.setEncryptionTime(encryptionTime);

            // 预热解密
            for (int i = 0; i < 3; i++) {
                try {
                    algorithm.decrypt(encryptedData, key);
                } catch (Exception e) {
                    // 忽略预热中的错误
                }
            }

            // 测试解密性能
            startTime = System.currentTimeMillis();
            byte[] decryptedData = algorithm.decrypt(encryptedData, key);
            long decryptionTime = System.currentTimeMillis() - startTime;

            result.setDecryptionTime(decryptionTime);

            // 验证正确性
            if (!Arrays.equals(testData, decryptedData)) {
                result.setSuccessful(false);
                result.setErrorMessage("解密后数据不匹配");
            }

        } catch (Exception e) {
            result.setSuccessful(false);
            result.setErrorMessage(e.getMessage());
        }

        results.add(result);
    }

    public void testAllAlgorithms(byte[] testData) {
        String key;
        try {
            key = com.guohao.tools.sys.AESEncryption.generateKeyBase64();
        } catch (Exception e) {
            throw new RuntimeException("生成AES密钥失败", e);
        }

        System.out.println("\n=== 开始性能测试 ===");
        System.out.println("测试数据大小: " + testData.length + " 字节");
        System.out.println();

        // 测试所有算法
        EncryptionFactory.AlgorithmType[] algorithms = EncryptionFactory.AlgorithmType.values();

        for (EncryptionFactory.AlgorithmType algType : algorithms) {
            System.out.print("测试 " + algType + "... ");

            try {
                EncryptionAlgorithm algorithm = EncryptionFactory.createAlgorithm(algType);
                String algKey = key;
                if (algorithm instanceof com.guohao.tools.ays.RSAEncryption rsa) {
                    String pub = rsa.getPublicKeyBase64();
                    String priv = rsa.getPrivateKeyBase64();
                    algKey = "pub:" + pub + ";priv:" + priv;
                } else if (algorithm instanceof com.guohao.tools.ays.SM2Encryption sm2) {
                    String pub = sm2.getPublicKeyBase64();
                    String priv = sm2.getPrivateKeyBase64();
                    algKey = "pub:" + pub + ";priv:" + priv;
                } else if (algorithm instanceof com.guohao.tools.ays.ECIESEncryption ecies) {
                    String pub = ecies.getPublicKeyBase64();
                    String priv = ecies.getPrivateKeyBase64();
                    algKey = "pub:" + pub + ";priv:" + priv;
                }
                testAlgorithm(algorithm, testData, algKey);
                System.out.println("完成");
            } catch (Exception e) {
                PerformanceResult result = new PerformanceResult(algType.toString());
                result.setOriginalSize(testData.length);
                result.setSuccessful(false);
                result.setErrorMessage(e.getMessage());
                results.add(result);
                System.out.println("失败: " + e.getMessage());
            }
        }
    }

    public void printResults() {
        System.out.println("\n" + "=".repeat(120));
        System.out.println("                                    性能测试结果报告");
        System.out.println("=".repeat(120));

        System.out.printf("%-25s %-10s %-12s %-12s %-12s %-15s %-15s %-10s%n",
                "算法名称", "状态", "原始大小", "加密大小", "大小比例", "加密速度", "解密速度", "总时间");
        System.out.println("-".repeat(120));

        for (PerformanceResult result : results) {
            if (result.isSuccessful()) {
                System.out.printf("%-25s %-10s %-12s %-12s %-12s %-15s %-15s %-10s%n",
                        result.getAlgorithmName(),
                        "成功",
                        formatSize(result.getOriginalSize()),
                        formatSize(result.getEncryptedSize()),
                        df.format(result.getSizeRatio()) + "x",
                        speedFormat.format(result.getEncryptionSpeed()) + " B/s",
                        speedFormat.format(result.getDecryptionSpeed()) + " B/s",
                        (result.getEncryptionTime() + result.getDecryptionTime()) + "ms"
                );
            } else {
                System.out.printf("%-25s %-10s %-60s%n",
                        result.getAlgorithmName(),
                        "失败",
                        result.getErrorMessage()
                );
            }
        }

        System.out.println("-".repeat(120));

        // 统计信息
        printStatistics();
    }

    private void printStatistics() {
        List<PerformanceResult> successful = results.stream()
                .filter(PerformanceResult::isSuccessful)
                .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);

        if (successful.isEmpty()) {
            System.out.println("没有成功的测试结果");
            return;
        }

        System.out.println("\n=== 统计分析 ===");

        // 最快加密算法
        PerformanceResult fastestEncryption = successful.stream()
                .min(Comparator.comparing(PerformanceResult::getEncryptionTime))
                .orElse(null);

        if (fastestEncryption != null) {
            System.out.println("最快加密: " + fastestEncryption.getAlgorithmName() +
                    " (" + fastestEncryption.getEncryptionTime() + "ms)");
        }

        // 最快解密算法
        PerformanceResult fastestDecryption = successful.stream()
                .min(Comparator.comparing(PerformanceResult::getDecryptionTime))
                .orElse(null);

        if (fastestDecryption != null) {
            System.out.println("最快解密: " + fastestDecryption.getAlgorithmName() +
                    " (" + fastestDecryption.getDecryptionTime() + "ms)");
        }

        // 最小文件膨胀
        PerformanceResult smallestRatio = successful.stream()
                .min(Comparator.comparing(PerformanceResult::getSizeRatio))
                .orElse(null);

        if (smallestRatio != null) {
            System.out.println("最小膨胀: " + smallestRatio.getAlgorithmName() +
                    " (" + df.format(smallestRatio.getSizeRatio()) + "x)");
        }

        // 最大文件膨胀
        PerformanceResult largestRatio = successful.stream()
                .max(Comparator.comparing(PerformanceResult::getSizeRatio))
                .orElse(null);

        if (largestRatio != null) {
            System.out.println("最大膨胀: " + largestRatio.getAlgorithmName() +
                    " (" + df.format(largestRatio.getSizeRatio()) + "x)");
        }

        // 按算法类型分组分析
        System.out.println("\n=== 按算法类型分析 ===");

        Map<String, List<PerformanceResult>> groupedResults = new HashMap<>();
        for (PerformanceResult result : successful) {
            String category = categorizeAlgorithm(result.getAlgorithmName());
            groupedResults.computeIfAbsent(category, k -> new ArrayList<>()).add(result);
        }

        for (Map.Entry<String, List<PerformanceResult>> entry : groupedResults.entrySet()) {
            System.out.println("\n" + entry.getKey() + ":");

            double avgEncTime = entry.getValue().stream()
                    .mapToLong(PerformanceResult::getEncryptionTime)
                    .average().orElse(0.0);

            double avgDecTime = entry.getValue().stream()
                    .mapToLong(PerformanceResult::getDecryptionTime)
                    .average().orElse(0.0);

            double avgRatio = entry.getValue().stream()
                    .mapToDouble(PerformanceResult::getSizeRatio)
                    .average().orElse(0.0);

            System.out.println("  平均加密时间: " + df.format(avgEncTime) + "ms");
            System.out.println("  平均解密时间: " + df.format(avgDecTime) + "ms");
            System.out.println("  平均大小比例: " + df.format(avgRatio) + "x");
        }
    }

    private String categorizeAlgorithm(String algorithmName) {
        if (algorithmName.contains("AES") || algorithmName.contains("SM4")) {
            return "对称加密";
        }
        return "非对称混合加密";
    }

    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + "B";
        if (bytes < 1024 * 1024) return df.format(bytes / 1024.0) + "KB";
        return df.format(bytes / (1024.0 * 1024.0)) + "MB";
    }

    public void clearResults() {
        results.clear();
    }

    // 批量测试不同大小的数据
    public void batchTest() {
        int[] sizes = {1024, 10240, 102400}; // 1KB, 10KB, 100KB
        String[] dataTypes = {"随机数据", "文本数据", "重复数据"};

        for (int i = 0; i < sizes.length; i++) {
            for (int j = 0; j < dataTypes.length; j++) {
                System.out.println("\n" + "=".repeat(80));
                System.out.println("测试 " + dataTypes[j] + " - " + formatSize(sizes[i]));
                System.out.println("=".repeat(80));

                byte[] testData;
                switch (j) {
                    case 0:
                        testData = TestDataGenerator.generateRandomData(sizes[i]);
                        break;
                    case 1:
                        testData = TestDataGenerator.generateTextData(sizes[i]);
                        break;
                    case 2:
                        testData = TestDataGenerator.generateRepeatingData(sizes[i]);
                        break;
                    default:
                        continue;
                }

                clearResults();
                testAllAlgorithms(testData);
                printResults();
            }
        }
    }
}

// 主测试程序
public class EncryptionPerformanceTest {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        EncryptionPerformanceTester tester = new EncryptionPerformanceTester();

        System.out.println("=== 加密算法性能测试程序 ===");
        System.out.println("1. 快速测试 (1KB随机数据)");
        System.out.println("2. 标准测试 (10KB随机数据)");
        System.out.println("3. 大文件测试 (100KB随机数据)");
        System.out.println("4. 批量测试 (多种数据类型和大小)");
        System.out.println("5. 自定义测试");
        System.out.println("6. 创建测试文件");

        System.out.print("请选择测试模式 (1-6): ");
        int choice = scanner.nextInt();

        try {
            switch (choice) {
                case 1:
                    System.out.println("执行快速测试...");
                    byte[] quickData = TestDataGenerator.generateRandomData(1024);
                    tester.testAllAlgorithms(quickData);
                    tester.printResults();
                    break;

                case 2:
                    System.out.println("执行标准测试...");
                    byte[] standardData = TestDataGenerator.generateRandomData(10240);
                    tester.testAllAlgorithms(standardData);
                    tester.printResults();
                    break;

                case 3:
                    System.out.println("执行大文件测试...");
                    byte[] largeData = TestDataGenerator.generateRandomData(102400);
                    tester.testAllAlgorithms(largeData);
                    tester.printResults();
                    break;

                case 4:
                    System.out.println("执行批量测试...");
                    tester.batchTest();
                    break;

                case 5:
                    scanner.nextLine(); // 消费换行符
                    System.out.print("请输入数据大小(字节): ");
                    int size = scanner.nextInt();
                    scanner.nextLine();

                    System.out.println("选择数据类型:");
                    System.out.println("1. 随机数据");
                    System.out.println("2. 文本数据");
                    System.out.println("3. 重复数据");
                    System.out.print("请选择 (1-3): ");
                    int dataType = scanner.nextInt();

                    byte[] customData;
                    switch (dataType) {
                        case 1:
                            customData = TestDataGenerator.generateRandomData(size);
                            break;
                        case 2:
                            customData = TestDataGenerator.generateTextData(size);
                            break;
                        case 3:
                            customData = TestDataGenerator.generateRepeatingData(size);
                            break;
                        default:
                            System.out.println("无效选择，使用随机数据");
                            customData = TestDataGenerator.generateRandomData(size);
                    }

                    tester.testAllAlgorithms(customData);
                    tester.printResults();
                    break;

                case 6:
                    System.out.println("创建测试文件...");
                    TestDataGenerator.createTestFiles();
                    break;

                default:
                    System.out.println("无效选择");
            }

        } catch (Exception e) {
            System.err.println("测试过程中发生错误: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }

        System.out.println("\n测试完成!");
    }

    // 单独的文件测试方法
    public static void testFile(String filename) {
        try {
            byte[] fileData = Files.readAllBytes(Paths.get(filename));
            EncryptionPerformanceTester tester = new EncryptionPerformanceTester();

            System.out.println("测试文件: " + filename);
            tester.testAllAlgorithms(fileData);
            tester.printResults();

        } catch (IOException e) {
            System.err.println("无法读取文件: " + e.getMessage());
        }
    }

    // 简单基准测试
    public static void simpleBenchmark() {
        System.out.println("=== 简单基准测试 ===");

        byte[] testData = TestDataGenerator.generateRandomData(10240); // 10KB
        String key;
        try {
            key = com.guohao.tools.sys.AESEncryption.generateKeyBase64();
        } catch (Exception e) {
            throw new RuntimeException("生成AES密钥失败", e);
        }

        try {
            // 测试每个算法的基本性能
            EncryptionFactory.AlgorithmType[] algorithms = EncryptionFactory.AlgorithmType.values();

            System.out.printf("%-25s %-15s %-15s %-15s%n",
                    "算法", "加密时间(ms)", "解密时间(ms)", "文件膨胀率");
            System.out.println("-".repeat(70));

            for (EncryptionFactory.AlgorithmType algType : algorithms) {
                try {
                    EncryptionAlgorithm algorithm = EncryptionFactory.createAlgorithm(algType);

                    // 测试加密
                    long startTime = System.currentTimeMillis();
                    String algKey = key;
                if (algorithm instanceof com.guohao.tools.ays.RSAEncryption rsa) {
                    String pub = rsa.getPublicKeyBase64();
                    String priv = rsa.getPrivateKeyBase64();
                    algKey = "pub:" + pub + ";priv:" + priv;
                } else if (algorithm instanceof com.guohao.tools.ays.SM2Encryption sm2) {
                    String pub = sm2.getPublicKeyBase64();
                    String priv = sm2.getPrivateKeyBase64();
                    algKey = "pub:" + pub + ";priv:" + priv;
                } else if (algorithm instanceof com.guohao.tools.ays.ECIESEncryption ecies) {
                    String pub = ecies.getPublicKeyBase64();
                    String priv = ecies.getPrivateKeyBase64();
                    algKey = "pub:" + pub + ";priv:" + priv;
                }
                    byte[] encrypted = algorithm.encrypt(testData, algKey);
                    long encTime = System.currentTimeMillis() - startTime;

                    // 测试解密
                    startTime = System.currentTimeMillis();
                    algorithm.decrypt(encrypted, algKey);
                    long decTime = System.currentTimeMillis() - startTime;

                    double ratio = (double) encrypted.length / testData.length;

                    System.out.printf("%-25s %-15d %-15d %-15.2f%n",
                            algorithm.getAlgorithmName(), encTime, decTime, ratio);

                } catch (Exception e) {
                    System.out.printf("%-25s %-45s%n",
                            algType.toString(), "错误: " + e.getMessage());
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
