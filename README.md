# 配置文件加密 MVP（Spring Boot 集成组件）

这是一个用于 **Spring Boot** 的加密配置加载组件（MVP），用于让配置文件在磁盘上保持加密状态，运行时由组件安全解密并加载。适合 MB 级配置文件，支持流式加解密，密钥来自环境变量，并支持密钥轮换。

## 这个项目是 Spring Boot 还是 Spring？

这是 **Spring Boot 集成组件**。当前项目本身不是一个完整的 Spring Boot 应用，而是一个可以被 Spring Boot 微服务引入的库/组件。

## 功能概览

- 带算法标识的加密格式（头部包含 magic/algorithm/keyId）。
- 环境变量 Key Ring 支持多密钥与轮换。
- Spring Boot `PropertySourceLoader` 自动解密 `.enc` 文件并加载 YAML/Properties（使用 `tools` 的算法实现）。
- 提供简单 CLI 工具用于加密/解密文件。

## 支持算法（已清理旧实现）

- AES-GCM（对称加密，推荐用于配置文件加密）
- SM4-GCM（对称加密，依赖 BouncyCastle）
- RSA 混合加密（RSA 加密 AES 数据密钥 + AES-GCM 加密正文）
- SM2 混合加密（SM2 加密 SM4 数据密钥 + SM4-GCM 加密正文，依赖 BouncyCastle）
- ECIES 混合加密（ECIES 加密 AES 数据密钥 + AES-GCM 加密正文，依赖 BouncyCastle）

不可逆或不安全的旧算法已删除（如 ECC 哈希占位、Rabin 简化版、DES、群论算法简化实现等）。

## 使用方式（AES/SM4/RSA/SM2/ECIES）

编译 core：

```text
mvn -q -DskipTests -pl configenc-core clean compile
```

如需使用 SM2/SM4/ECIES，请先生成包含依赖的 classpath：

```text
mvn -q -DskipTests -pl configenc-core dependency:build-classpath "-Dmdep.outputFile=target/cp.txt"
$cp = "configenc-core/target/classes;" + (Get-Content -Raw configenc-core/target/cp.txt)
```

运行交互式加密工具（用于算法演示/文件加解密）：

```text
java -cp configenc-core/target/classes com.guohao.Main
```

如需使用 SM2/SM4/ECIES，使用包含依赖的 classpath：

```text
java -cp "$cp" com.guohao.Main
```

### 对称算法（AES-GCM / SM4-GCM）

- 选择算法后，输入 **Base64 密钥**。
- 密钥长度推荐 16/24/32 字节（SM4 固定 16 字节）；如果长度不匹配，会用 SHA-256 归一化。

示例（生成 Base64 密钥）：

```text
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$k = [Convert]::ToBase64String($bytes)
```

### 混合算法（RSA / SM2 / ECIES）

- 加密时需要 **公钥**，解密时需要 **私钥**。
- 输入格式：`pub:BASE64` 或 `priv:BASE64`（也可以直接粘贴 Base64）。

可用 JShell 快速生成一对密钥（示例：SM2）：

```text
jshell --class-path configenc-core/target/classes
jshell> import com.guohao.tools.ays.SM2Encryption;
jshell> SM2Encryption sm2 = new SM2Encryption();
jshell> System.out.println(sm2.getPublicKeyBase64());
jshell> System.out.println(sm2.getPrivateKeyBase64());
```

RSA 与 ECIES 类似，分别使用：

```text
com.guohao.tools.ays.RSAEncryption
com.guohao.tools.ays.ECIESEncryption
```

## configenc 与 tools 的关系

`configenc` 不再内置固定算法，而是**直接调用 `tools` 的算法实现**。加密文件头会写入算法标识（例如 `AES`、`SM4`、`RSA`、`SM2`、`ECIES`），解密时按头部自动选择算法。

## configenc CLI 用法

```text
java -cp configenc-core/target/classes com.guohao.configenc.tool.ConfigEncryptorCli encrypt <algorithm> <input> <output> [keyId] [key]
java -cp configenc-core/target/classes com.guohao.configenc.tool.ConfigEncryptorCli decrypt <input> <output>
```

说明：涉及 SM2/SM4/ECIES 时请使用 `$cp`（包含 BouncyCastle 依赖）。

示例（AES）：

```text
java -cp configenc-core/target/classes com.guohao.configenc.tool.ConfigEncryptorCli encrypt AES application.yml application.yml.enc default $BASE64_AES_KEY
```

示例（SM2，公钥加密，私钥解密）：

```text
java -cp "$cp" com.guohao.configenc.tool.ConfigEncryptorCli encrypt SM2 application.yml application.yml.enc default pub:BASE64_PUBLIC_KEY
java -cp "$cp" com.guohao.configenc.tool.ConfigEncryptorCli decrypt application.yml.enc application.yml.dec
```

## 工程结构

```
FileEncryption/
├── configenc-core/            # 加密组件主体代码
│   ├── src/main/java/com/guohao/configenc
│   └── src/main/resources/META-INF
├── demo/                      # Spring Boot 集成验证 Demo
│   ├── src/main/java/com/guohao/demo
│   └── src/main/resources
└── pom.xml                    # 父工程聚合 POM
```

## 快速开始

### 1) 生成 Base64 密钥

密钥推荐 16/24/32 字节，示例（Java）：

```java
byte[] raw = new byte[32];
new java.security.SecureRandom().nextBytes(raw);
String b64 = java.util.Base64.getEncoder().encodeToString(raw);
System.out.println(b64);
```

### 2) 配置环境变量

```text
CONFIG_ENC_KEYRING=key1:BASE64_KEY_1,key2:BASE64_KEY_2
CONFIG_ENC_ACTIVE_KEY_ID=key1
```

### 3) 加密配置文件

```text
java -cp configenc-core/target/configenc-core-1.0-SNAPSHOT.jar com.guohao.configenc.tool.ConfigEncryptorCli encrypt AES application.yml application.yml.enc default $BASE64_AES_KEY
```

### 4) 在 Spring Boot 中使用

```text
spring.config.import=classpath:application.yml.enc
```

`.enc` 会被自动解密，并根据原始文件名后缀（yml/yaml/properties）选择解析器。

## Demo 使用（Spring Boot 集成验证）

在项目根目录执行：

1) 设置密钥（以 AES 为例）

```text
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$k = [Convert]::ToBase64String($bytes)
$env:CONFIG_ENC_KEYRING = "key1:$k"
$env:CONFIG_ENC_ACTIVE_KEY_ID = "key1"
```

2) 准备配置并加密

```text
@"
app:
  name: demo-service
  port: 9090
"@ | Set-Content -Encoding UTF8 demo\src\main\resources\application.yml

mvn -q -DskipTests -pl configenc-core compile
java -cp configenc-core/target/classes com.guohao.configenc.tool.ConfigEncryptorCli encrypt AES demo/src/main/resources/application.yml demo/src/main/resources/application.yml.enc default $k
Remove-Item demo/src/main/resources/application.yml
```

3) 打包并运行 Demo

```text
mvn -q -DskipTests -pl demo -am clean package
java -jar demo/target/configenc-demo-1.0-SNAPSHOT.jar --spring.main.web-application-type=none --spring.main.banner-mode=off
```

期望输出（关键行）：

```text
Loaded from encrypted config:
app.name=demo-service
app.port=9090
```

## Demo 切换不同加密方法

Demo 的 `spring.config.import=classpath:application.yml.enc` 已固定。要切换算法，只需要**重新加密** `application.yml` 即可。

### 切换到 AES/SM4（对称算法）

1) 生成并设置对称密钥（以 AES 为例）：

```text
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$k = [Convert]::ToBase64String($bytes)
$env:CONFIG_ENC_KEYRING = "key1:$k"
$env:CONFIG_ENC_ACTIVE_KEY_ID = "key1"
```

2) 重新加密并运行：

```text
java -cp configenc-core/target/classes com.guohao.configenc.tool.ConfigEncryptorCli encrypt AES demo/src/main/resources/application.yml demo/src/main/resources/application.yml.enc default $k
Remove-Item demo/src/main/resources/application.yml
mvn -q -DskipTests -pl demo -am clean package
java -jar demo/target/configenc-demo-1.0-SNAPSHOT.jar --spring.main.web-application-type=none --spring.main.banner-mode=off
```

### 切换到 RSA/SM2/ECIES（混合算法）

1) 生成公私钥（以 SM2 为例）：

```text
jshell --class-path "$cp"
jshell> import com.guohao.tools.ays.SM2Encryption;
jshell> SM2Encryption sm2 = new SM2Encryption();
jshell> System.out.println(sm2.getPublicKeyBase64());
jshell> System.out.println(sm2.getPrivateKeyBase64());
```

2) 设置 **私钥** 到环境变量（用于解密）：

```text
$env:CONFIG_ENC_KEYRING = "key1:BASE64_PRIVATE_KEY"
$env:CONFIG_ENC_ACTIVE_KEY_ID = "key1"
```

3) 用 **公钥** 重新加密并运行：

```text
java -cp "$cp" com.guohao.configenc.tool.ConfigEncryptorCli encrypt SM2 demo/src/main/resources/application.yml demo/src/main/resources/application.yml.enc default pub:BASE64_PUBLIC_KEY
Remove-Item demo/src/main/resources/application.yml
mvn -q -DskipTests -pl demo -am clean package
java -jar demo/target/configenc-demo-1.0-SNAPSHOT.jar --spring.main.web-application-type=none --spring.main.banner-mode=off
```

### 正确结果（所有算法一致）

启动时应看到：

```text
Loaded from encrypted config:
app.name=demo-service
app.port=9090
```

## 环境变量说明

- `CONFIG_ENC_KEYRING`: 多密钥列表，使用 `,` 或 `;` 分隔。
  - 格式：`keyId:BASE64` 或 `keyId=BASE64`
- `CONFIG_ENC_ACTIVE_KEY_ID`: 当前用于加密的新密钥 ID。
- `CONFIG_ENC_KEY`: 仅单密钥模式（Base64），当未提供 Key Ring 时启用。
- `CONFIG_ENC_KEY_ID`: 单密钥模式的 KeyId（默认 `default`）。

说明：
- 对称算法（AES/SM4）：KeyRing 中存 Base64 对称密钥。
- 混合算法（RSA/SM2/ECIES）：KeyRing 中存 **私钥**（Base64），解密时使用。

## 密钥轮换

1) 将新密钥添加到 `CONFIG_ENC_KEYRING`。
2) 切换 `CONFIG_ENC_ACTIVE_KEY_ID` 为新 keyId，用于新加密。
3) 旧文件无需立刻重加密，解密会根据文件头中的 keyId 自动选择密钥。

## 加密格式（当前）

- Magic: `CFEC`
- Algorithm length + Algorithm（UTF-8，值为 `AES`/`SM4`/`RSA`/`SM2`/`ECIES`）
- KeyId length + KeyId（UTF-8）
- Ciphertext（算法输出）

## 备注

- 对称算法若密钥不是 16/24/32 字节，会用 SHA-256 归一化。
- `configenc` 已按流式方式调用 `tools` 算法。
- YAML 解析会将解密后的字节加载到内存。

