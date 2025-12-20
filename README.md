# Tool - 多功能生成工具箱

一个 **功能不算强大，但很杂很全的 Python 命令行工具集**。  
从编码解码到卡密生成，从加密解密到格式转换，适合折腾、学习、日常小工具使用。

> 作者小声逼逼：部分功能使用了 AI 辅助

---

## 主要特性

-  **多功能集成**：集成 20+ 种常用/奇怪/实用工具
-  **模块化设计**：每个工具独立运行，互不干扰
-  **易于使用**：菜单式命令行界面，目前僅支持中文
-  **可扩展**：支持自定义格式、模板和配置

---

## 功能列表

### 卡密生成器
- 支持多种格式模板  
  - 魔理沙  
  - UUID  
  - Drip  
  - 雪碧  
  - MinecraftUnBan 等
- 支持生成 **带账号信息的 Minecraft 卡密**
- 入侵卡网动画效果（中二但好玩）
- 高级配置选项  
  - 订单号  
  - 格式  
  - 分组  
  - 数量  

---

### 编码 / 解码工具
- Hex 编码 / 解码
- Base64 编码 / 解码
- URL 编码 / 解码

---

### 加密工具
- RSA  
  - 加密 / 解密  
  - 签名 / 验签
- AES-GCM 加密 / 解密
- 国密 SM2 加密 / 解密
- CSR 证书生成 / 查看

---

### 哈希工具
- MD5
- SHA1
- SHA256
- SHA512
- 支持 **字符串 / 文件哈希计算**

---

### 各类生成工具
- UUID 生成器（支持自定义格式）
- HWID 生成器
- 随机账号生成  
  - 邮箱  
  - 密码  
  - Minecraft 账号
- 漫画图片生成器（A4 模板）

---

### 格式转换工具
- JSON 美化 / 压缩
- JavaScript 美化 / 压缩
- HTML / CSS / YAML / XML 格式化
- 图片格式转换

---

### 其他工具
- 二维码 / 条形码生成
- 4399 账号转 Cookie
- Google 翻译
- Python 代码编译
- 身份证生成器
- 柏林噪声生成器
- 图片 / 视频 转字符艺术

---

## 快速开始

### 系统要求
- Python **3.7+**
- 支持 Windows / Linux / macOS

---

## 使用效果
<img width="923" height="620" alt="Screenshot 2025-12-20 091155" src="https://github.com/user-attachments/assets/840c9384-c2b6-4dd5-b5cd-1b02e6484940" />
<img width="509" height="904" alt="Screenshot 2025-12-20 091328" src="https://github.com/user-attachments/assets/a28cee78-a3f1-4785-9dae-390b5d381ca8" />
<img width="660" height="992" alt="image" src="https://github.com/user-attachments/assets/3223496a-575d-4453-9002-9201db889696" />
<img width="434" height="923" alt="image" src="https://github.com/user-attachments/assets/134ad352-9cba-4357-a10b-b739b8895942" />

### 安装方法

```bash
git clone https://github.com/SaonvWart/Tool.git
cd Tool
python main.py
