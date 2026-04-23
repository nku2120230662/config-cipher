# config-cipher — Spring Boot 配置文件加密组件

把敏感配置（数据库口令、第三方 API key 等）以**密文**形式提交进仓库，在 Spring Boot 启动时由组件**透明解密**。应用代码无需任何修改，`@Value` 注入的就是解密后的值。

密钥**永远不进 git**——通过环境变量、JVM 系统属性或外部密钥文件在运行时注入。

---

## 核心价值

| 保护场景 | 效果 |
|---|---|
| 仓库泄漏（git / 镜像 / jar） | 只拿到密文，无法还原配置 |
| 密文被篡改（哪怕 1 bit） | GCM AEAD tag 失配 → 启动失败 |
| 运行环境有 key 但拿不到密文 | 单独拿 key 没有意义 |
| 配套 K8s/Vault 等 secret manager | 天然兼容，key 挂成文件或注入环境变量 |

安全属性：
- 所有加密走 **AEAD**（AES-GCM / SM4-GCM），同时保证机密性 + 完整性
- 混合加密（RSA/SM2/ECIES + 对称）将封包密钥一起绑进 GCM AAD（v2 格式）
- 密钥长度**严格校验** 16/24/32 字节（AES）/ 16 字节（SM4），拒绝短密钥
- 文件格式 magic + version，可平滑演进

---

## 支持的算法

| 算法 | 类型 | 适用场景 | 依赖 |
|---|---|---|---|
| **AES-GCM** | 对称 | 一般推荐 | JDK |
| **SM4-GCM** | 对称 | 国密合规 | BouncyCastle |
| **RSA** 混合 | RSA-OAEP-SHA256 + AES-GCM | 公/私钥分离 | JDK |
| **SM2** 混合 | SM2 + SM4-GCM | 国密合规 | BouncyCastle |
| **ECIES** 混合 | ECIES + AES-GCM | 轻量公钥方案 | BouncyCastle |

---

## 工程结构

```
config-cipher/
├── config-cipher-core/     # 加密库（算法、文件格式、Spring SPI、CLI）
├── demo/                   # 示例 Spring Boot 应用
└── pom.xml                 # 聚合 POM
```

---

## 典型使用：打包分发给他人

这个工具最自然的场景是：**你在自己机器上加密配置 → 打包 jar → 分发给他人 → 对方拿到密钥后启动**。密文走普通渠道（邮件/网盘/仓库），密钥走安全渠道（1Password 分享 / Signal / Vault）。

### 第 1 步：生成密钥

```bash
# AES-256 密钥（44 字符 Base64）
java -cp config-cipher-core/target/classes -e 'System.out.println(com.guohao.tools.sys.AESEncryption.generateKeyBase64())'
# 或交互式
java -cp config-cipher-core/target/classes com.guohao.Main   # 选 "演示/生成"
```

PowerShell 直出：

```powershell
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[Convert]::ToBase64String($bytes)
```

### 第 2 步：加密配置

明文 `app.yml`（临时文件，**绝不进 git**）：

```yaml
app:
  name: demo-service
  db:
    password: SuperSecret123
```

加密：

```bash
java -cp config-cipher-core/target/classes \
  com.guohao.configcipher.tool.ConfigCipherCli encrypt \
  AES app.yml demo/src/main/resources/application.yml.enc default "$AES_KEY"

rm app.yml
```

（使用 SM4/SM2/ECIES 时需要把 BouncyCastle 依赖加进 classpath，详见下方 CLI 一节。）

### 第 3 步：让 Spring Boot 自动加载 `.enc`

`demo/src/main/resources/application.properties` 里一行：

```properties
spring.config.import=classpath:application.yml.enc
```

### 第 4 步：打包

```bash
mvn -q -DskipTests clean package
```

产物 `demo/target/config-cipher-demo-1.0-SNAPSHOT.jar` 里有**密文**、有**解密组件**、**没有密钥**。

### 第 5 步：接收方启动

对方收到 jar 和密钥（分开两条渠道），任选一种方式注入密钥：

```bash
# 方式 A — 环境变量（Linux/macOS）
export CONFIG_CIPHER_KEY="aBc...XyZ="
java -jar config-cipher-demo-1.0-SNAPSHOT.jar

# 方式 B — JVM 系统属性（跨平台最简单）
java -Dconfig.cipher.key=aBc...XyZ= -jar config-cipher-demo-1.0-SNAPSHOT.jar

# 方式 C — 密钥文件（推荐生产 / K8s / Vault 场景）
echo -n "aBc...XyZ=" > /run/secrets/app.key
chmod 400 /run/secrets/app.key
export CONFIG_CIPHER_KEY_FILE=/run/secrets/app.key
java -jar config-cipher-demo-1.0-SNAPSHOT.jar
```

成功输出：

```
Loaded from encrypted config:
app.name=demo-service
app.port=9090
```

**没设密钥？** 启动会报错并列出所有支持的输入方式。

---

## 密钥输入来源（完整表）

按优先级查找，**第一个命中的非空值生效**：

| # | 来源 | 单 key / Keyring | 说明 |
|---|---|---|---|
| 1 | `-Dconfig.cipher.keyring` | Keyring | JVM 系统属性，`keyId:BASE64,...` |
| 2 | `CONFIG_CIPHER_KEYRING` | Keyring | 环境变量 |
| 3 | `-Dconfig.cipher.keyring.file` | Keyring | 文件路径；内容同 keyring 字符串，也支持每行一条 |
| 4 | `CONFIG_CIPHER_KEYRING_FILE` | Keyring | 环境变量指向文件 |
| 5 | `-Dconfig.cipher.key` | 单 key | JVM 系统属性 |
| 6 | `CONFIG_CIPHER_KEY` | 单 key | 环境变量 |
| 7 | `-Dconfig.cipher.key.file` | 单 key | 文件路径，内容就是 Base64 key |
| 8 | `CONFIG_CIPHER_KEY_FILE` | 单 key | 环境变量指向文件 |

辅助变量：
- `-Dconfig.cipher.active.key.id` / `CONFIG_CIPHER_ACTIVE_KEY_ID`：Keyring 多 key 下指定当前加密用哪个 keyId
- `-Dconfig.cipher.key.id` / `CONFIG_CIPHER_KEY_ID`：单 key 模式下设置 keyId（默认 `default`）

---

## 密钥文件的写法

**单 key 文件**（`CONFIG_CIPHER_KEY_FILE` 指向）：

```
aBc...XyZ=
```

内容就是一串 Base64，允许末尾换行。文件建议 `chmod 400`。

**Keyring 文件**（`CONFIG_CIPHER_KEYRING_FILE` 指向）：

```
key-2025:NEW_BASE64_KEY
key-2024:OLD_BASE64_KEY
```

逗号/分号/换行三种分隔任选。

---

## 密钥轮换

多 key 并存 → 新文件用新 keyId 加密 → 老文件靠老 keyId 还能解 → 老文件全部刷完后再下线老 key：

```
CONFIG_CIPHER_KEYRING_FILE=/etc/app/keys
CONFIG_CIPHER_ACTIVE_KEY_ID=key-2025   # 新加密用这个

# /etc/app/keys
key-2025:NEW_BASE64_KEY              # 新 key
key-2024:OLD_BASE64_KEY              # 过渡期保留，老 .enc 用它解密
```

解密端根据密文 header 里的 keyId 自动选 key，不需要代码改动。

---

## 文件格式

```
Magic "CFEC" (4B)
Version (1B)            = 0x02 (V2)
AlgorithmId len (1B) + AlgorithmId (UTF-8, "AES"/"SM4"/"RSA"/"SM2"/"ECIES")
KeyId len (1B) + KeyId (UTF-8)
Algorithm-specific body:
  对称：version(1B) + iv_len(1B) + iv(12B) + GCM_ciphertext_with_tag
  混合：version(1B) + encKey_len(2B) + encKey + iv_len(1B) + iv(12B) + GCM_ciphertext_with_tag
        (v2 将 version ‖ encKey ‖ iv 绑入 GCM AAD)
```

V1 密文仍可读（向后兼容），新加密一律写 V2。

---

## CLI 参考

```bash
# 加密
java -cp config-cipher-core/target/classes \
  com.guohao.configcipher.tool.ConfigCipherCli encrypt \
  <AES|SM4|RSA|SM2|ECIES> <input> <output> [keyId] [key]

# 解密（算法和 keyId 从文件头自动读出）
java -cp config-cipher-core/target/classes \
  com.guohao.configcipher.tool.ConfigCipherCli decrypt <input> <output>
```

使用 SM4/SM2/ECIES 需要把 BouncyCastle 加进 classpath：

```bash
mvn -q -pl config-cipher-core dependency:build-classpath -Dmdep.outputFile=target/cp.txt
CP="config-cipher-core/target/classes:$(cat config-cipher-core/target/cp.txt)"
java -cp "$CP" com.guohao.configcipher.tool.ConfigCipherCli encrypt SM2 ...
```

混合算法的 key 参数格式：`pub:BASE64` 或 `priv:BASE64`（分号分隔可同时提供）。

---

## 安全边界（这个工具**不做**什么）

- **不管密钥从哪来**：`CONFIG_CIPHER_*` 环境变量/文件由部署方（K8s Secret / Vault / systemd / CI）负责注入
- **不抗反编译**：jar 可被反编译，但代码里没有任何密钥硬编码，也没有密钥相关的魔法常量
- **不抗进程内存 dump**：持久化的 `String` key 没做主动清零（JVM GC 前可能滞留）
- **不做审计日志**：哪次解了哪把 key 目前不记录
- **不做密钥派生**：拒绝弱口令而不是 PBKDF2 stretch；需要口令→key 请在外部用 Argon2/PBKDF2 单独处理

这些都是**配置文件加密**合理的边界——目标是"拿到仓库 ≠ 拿到生产配置"，不是 HSM。

---

## Spring Boot 集成原理

[`config-cipher-core`](config-cipher-core) jar 里注册了 Spring Boot SPI：

```
META-INF/spring/org.springframework.boot.env.PropertySourceLoader
  → com.guohao.configcipher.EncryptedConfigPropertySourceLoader
```

Spring Boot 启动扫 classpath 发现这个 loader，凡是 `.enc` / `.yml.enc` / `.properties.enc` 后缀的资源都交给它处理：读 header → 查 KeyRing → 调对应算法解密 → 把明文字节交回给内置的 YAML/Properties loader 解析。

业务代码只需要：

```properties
spring.config.import=classpath:application.yml.enc
```

然后照常 `@Value("${app.db.password}")`，**看不到密文也看不到密钥**。
