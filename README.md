# Tool - 多功能生成工具箱
> Version: v0.5-release

---

一个 **功能不算强大，但很杂很全的 Python 命令行工具集**。  
从编码解码到卡密生成，从加密解密到格式转换，适合折腾、学习、日常小工具使用。

> 作者小声逼逼：部分功能使用了 AI 辅助

---

## 主要特性

-  **多功能集成**：集成 20+ 种常用/奇怪/实用工具
-  **模块化设计**：每个工具独立运行，互不干扰
-  **易于使用**：菜单式命令行界面，目前僅支持中文
-  **可扩展**：支持自定义格式、模板和配置
-  **自動更新**: 自動檢查版本並更新

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
- 支持 Windows

---

## 使用效果
<img width="1159" height="672" alt="QQ_1766195868495" src="https://github.com/user-attachments/assets/ba009b2a-f295-4c24-81b5-9020511b31db" /><img width="1159" height="672" alt="QQ_1766195894999" src="https://github.com/user-attachments/assets/9b071f7d-a209-43f9-be44-b5bc91d7522c" /><img width="500" height="928" alt="QQ_1766195932675" src="https://github.com/user-attachments/assets/49ba26a9-45e5-4a9a-867b-72eb2e983b7c" /><img width="717" height="388" alt="QQ_1766195982207" src="https://github.com/user-attachments/assets/2237dc1e-d014-4f4f-ae8a-d7ee4c6e60de" /><img width="490" height="633" alt="QQ_1766196010079" src="https://github.com/user-attachments/assets/377cc42e-887a-42d4-aa1e-1fe4fc78a883" />

### 安装方法

```bash
git clone https://github.com/SaonvWart/Tool.git
cd Tool
python main.py
