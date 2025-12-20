from __future__ import annotations
import os
import sys
import uuid
import base64
import json
import hashlib
import binascii
import re
import textwrap
import time
from pathlib import Path
import urllib.parse
from typing import Optional
import random
import string
from datetime import datetime

# 版本信息
Version = "v0.3-release"
Form = "python"

try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

from PIL import Image

try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

try:
    from gmssl import sm2, func as gmfunc
    GMSM_AVAILABLE = True
except Exception:
    GMSM_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

try:
    import qrcode
    QRCODE_AVAILABLE = True
except Exception:
    QRCODE_AVAILABLE = False

try:
    import barcode
    BARCODE_AVAILABLE = True
except Exception:
    BARCODE_AVAILABLE = False

try:
    import noise
    NOISE_AVAILABLE = True
except Exception:
    NOISE_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except Exception:
    NUMPY_AVAILABLE = False

try:
    import python_minifier
    MINIFIER_AVAILABLE = True
except Exception:
    MINIFIER_AVAILABLE = False

try:
    import cv2
    CV2_AVAILABLE = True
except Exception:
    CV2_AVAILABLE = False

import ast
import re

def translate_text(text):
    mapping = {'永': 'zzz', '久': 'zz', '周': 'z'}
    result = text
    for old, new in mapping.items():
        result = result.replace(old, new)
    return result

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def pause(msg="按回车继续..."):
    try:
        input(msg)
    except KeyboardInterrupt:
        print()

def print_header(title: str):
    clear_screen()
    print("="*40)
    print(title)
    print("="*40)

def safe_input(prompt: str = "") -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""
    except KeyboardInterrupt:
        print()
        return ""

def read_text_from_file(path: str, encoding='utf-8') -> str:
    return Path(path).read_text(encoding=encoding)

def read_bytes_from_file(path: str) -> bytes:
    return Path(path).read_bytes()

def write_bytes_to_file(path: str, data: bytes):
    Path(path).write_bytes(data)

def human_size(num: int) -> str:
    for unit in ['B','KB','MB','GB','TB','PB','EB','ZB','YB','BB','NB','DB','CB']:
        if num < 1024.0: return f"{num:.2f}{unit}"
        num /= 1024.0
    return f"{num:.2f}PB"

email_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'qq.com', 'protonmail.com', 'gmail.com' , 'icloud.com', 'mail.com', 'zoho.com', 'yandex.com', 'gmx.com', 'aol.com', 'live.com', 'inbox.com', 'fastmail.com', 'tutanota.com', 'hushmail.com', 'mailfence.com', 'runbox.com', 'posteo.de', 'startmail.com', '163.com', '126.com', 'sina.com', 'sohu.com', 'yeah.net', 'tom.com', '21cn.com', '189.cn', 'foxmail.com', 'aliyun.com', 'yeah.net', 'vip.qq.com', 'vip.163.com', 'vip.sina.com', 'vip.126.com', 'vip.tom.com' ,'yeah.com', 'live.cn', 'live.hk', 'live.com.cn', 'hotmail.co.uk', 'hotmail.fr', 'hotmail.de', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de', 'outlook.co.uk', 'outlook.fr', 'outlook.de']

name_prefixes = ['Player', 'Gamer', 'Miner', 'Crafter', 'Builder', 'Master', 'Pro', 'Elite', 'Sky', 'Hyper', 'Ultra', 'Super', 'Epic', 'Dark', 'Light', 'Shadow', 'Fire', 'Ice', 'Storm', 'Thunder' ,'Ninja', 'Warrior', 'Knight', 'Dragon', 'Phoenix', 'Wolf', 'Tiger', 'Eagle', 'Falcon', 'Rogue', 'Hunter', 'Wizard', 'Mage', 'Ranger', 'Assassin', 'Paladin', 'Druid', 'Berserker', 'Samurai', 'Viking', 'Spartan', 'Gladiator', 'Shadow', 'Phantom', 'Specter', 'Wraith', 'Reaper', 'Slayer', 'Hunter', 'Stalker', 'Tracker', 'Seeker', 'Voyager', 'Explorer', 'Adventurer', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '_', '.', '-', '!', '@', '#', '$', '%', '^', '&', '*', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'zero', 'the', 'best', 'legend', 'champion', 'king', 'queen', 'lord', 'lady', 'hero', 'master', 'ultimate', 'supreme', 'destroyer', 'conqueror', 'guardian', 'warden', 'sentinel', 'vindicator', 'avenger', 'defender', 'berserker', 'paladin', 'druid', 'ranger', 'assassin', 'samurai', 'viking', 'spartan', 'gladiator', 'shadow', 'phantom', 'specter', 'wraith', 'reaper', 'slayer', 'hunter', 'stalker', 'tracker', 'seeker', 'voyager', 'explorer', 'adventurer']

name_suffixes = ['Player', 'Gamer', 'Miner', 'Crafter', 'Builder', 'Master', 'Pro', 'Elite', 'Sky', 'Hyper', 'Ultra', 'Super', 'Epic', 'Dark', 'Light', 'Shadow', 'Fire', 'Ice', 'Storm', 'Thunder' ,'Ninja', 'Warrior', 'Knight', 'Dragon', 'Phoenix', 'Wolf', 'Tiger', 'Eagle', 'Falcon', 'Rogue', 'Hunter', 'Wizard', 'Mage', 'Ranger', 'Assassin', 'Paladin', 'Druid', 'Berserker', 'Samurai', 'Viking', 'Spartan', 'Gladiator', 'Shadow', 'Phantom', 'Specter', 'Wraith', 'Reaper', 'Slayer', 'Hunter', 'Stalker', 'Tracker', 'Seeker', 'Voyager', 'Explorer', 'Adventurer', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '_', '.', '-', '!', '@', '#', '$', '%', '^', '&', '*', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'zero', 'the', 'best', 'legend', 'champion', 'king', 'queen', 'lord', 'lady', 'hero', 'master', 'ultimate', 'supreme', 'destroyer', 'conqueror', 'guardian', 'warden', 'sentinel', 'vindicator', 'avenger', 'defender', 'berserker', 'paladin', 'druid', 'ranger', 'assassin', 'samurai', 'viking', 'spartan', 'gladiator', 'shadow', 'phantom', 'specter', 'wraith', 'reaper', 'slayer', 'hunter', 'stalker', 'tracker', 'seeker', 'voyager', 'explorer', 'adventurer']

capes_list = ['none', 'Pan', 'Migrator', 'Common', 'Menace', 'Home', 'Purple Heart', 'Mojang Office', 'Cherry Blossom', 'Follower\'s', '15th Anniversary']

def generate_random_password(length=12):
    """生成随机密码"""
    chars = string.ascii_letters + string.digits + '!@#$%^&*abcdefghijklmnopqrstuvwxyz1234567890'
    return ''.join(random.choices(chars, k=length))

def generate_random_email():
    """生成随机邮箱"""
    name_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 12)))
    domain = random.choice(email_domains)
    return f"{name_part}@{domain}"

def generate_random_minecraft_name():
    """生成随机Minecraft昵称"""
    prefix = random.choice(name_prefixes)
    suffix = random.choice(name_suffixes)
    return f"{prefix}{suffix}"

def generate_minecraft_account(account_type):
    """动态生成随机微软账号"""
    if account_type == '4':  
        
        level_data = [
            f"SW:{random.randint(1, 10)}",
            f"BW:{random.randint(1, 15)}",
            f"Arcade:{random.randint(1000, 50000)}",
        ]
        level = ' '.join(random.sample(level_data, k=random.randint(1, 3)))
        capes = random.choice(capes_list)
    elif account_type == '5':  
        
        level_parts = [
            f"BW:{random.randint(21, 50)}",
            f"SW:{random.randint(15, 40)}",
            f"SKB-level:{random.randint(30, 60)}",
            f"SKB-Kills:{random.randint(5000, 50000)}",
            f"UHC-Coins:{random.randint(10000, 100000)}",
            f"MW-Coins:{random.randint(10000, 100000)}",
            f"Arcade:{random.randint(500000, 10000000)}",
        ]
        level = ' '.join(random.sample(level_parts, k=random.randint(3, 5)))
        capes = ','.join(random.sample(capes_list, k=random.randint(2, 5)))
    else:
        
        level_data = [
            f"SW:{random.randint(1, 10)}",
            f"BW:{random.randint(1, 15)}",
            f"Arcade:{random.randint(1000, 50000)}",
        ]
        level = ' '.join(random.sample(level_data, k=random.randint(1, 3)))
        capes = random.choice(capes_list)
    
    return {
        'email': generate_random_email(),
        'password': generate_random_password(),
        'name': generate_random_minecraft_name(),
        'level': level,
        'capes': capes,
    }

def uuid_generator_menu():
    title = translate_text("UUID 生成器")
    uppercase = False
    separator = "-"
    braces = False
    count = 1
    to_b64 = False
    
    while True:
        print_header(title)
        print(translate_text("当前设置:"))
        print(f"  1) {translate_text('字母大小')}: {uppercase}")
        print(f"  2) {translate_text('分隔符')}: {repr(separator)}")
        print(f"  3) {translate_text('添加大括号')}: {braces}")
        print(f"  4) {translate_text('生成数量')}: {count}")
        print(f"  5) {translate_text('转 Base64')}: {to_b64}")
        print(f"  6) {translate_text('生成 UUID')}")
        cmd = safe_input(f"\n{translate_text('选择')} (1/2/3/4/5/6/0): ").strip().lower()
        
        if cmd == "1":
            uppercase = not uppercase
        elif cmd == "2":
            s = safe_input(translate_text("输入分隔符字符串"))
            separator = s
        elif cmd == "3":
            braces = not braces
        elif cmd == "4":
            n = safe_input(translate_text("请输入生成数量")).strip()
            try:
                count = max(1, int(n))
            except:
                print(translate_text("无效数字"))
                pause()
        elif cmd == "5":
            to_b64 = not to_b64
        elif cmd == "6":
            print_header(translate_text("生成结果"))
            for i in range(count):
                u = str(uuid.uuid4())
                if separator != "-":
                    if separator == "":
                        u = u.replace("-", "")
                    else:
                        u = u.replace("-", separator)
                if uppercase:
                    u = u.upper()
                if braces:
                    u = "{" + u + "}"
                if to_b64:
                    u = base64.b64encode(u.encode()).decode()
                print(u)
            pause()
        elif cmd == "0":
            return
        else:
            print(translate_text("无效选项"))
            pause()

def code_obfuscate_menu():
    print_header("Python 代码混淆")
    path = safe_input("输入 Python 文件路径: ").strip()
    if not Path(path).exists():
        print("文件不存在")
        pause()
        return

    code = read_text_from_file(path)
    obf = obfuscate_python_code(code)

    out = safe_input("输出文件名 (如 out.py): ").strip()
    Path(out).write_text(obf, encoding="utf-8")
    print("混淆完成:", out)
    pause()

def encdec_menu():
    title = translate_text("编码 / 解码工具")
    while True:
        print_header(title)
        print("1) Text -> Hex")
        print("2) Hex -> Text")
        print("3) Text -> Base64")
        print("4) Base64 -> Text")
        print("5) URL 编码/解码")
        print("0) " + translate_text("返回主菜单"))
        
        choice = safe_input(translate_text("选择") + ": ").strip()
        
        if choice == "1":
            s = safe_input(translate_text("输入文本") + ": ")
            encoding = safe_input(translate_text("编码") + " (utf-8): ").strip() or "utf-8"
            try:
                print(binascii.hexlify(s.encode(encoding)).decode())
            except Exception as e:
                print(translate_text("错误") + ":", e)
            pause()
        elif choice == "2":
            s = safe_input(translate_text("输入 hex") + ": ").strip()
            try:
                b = bytes.fromhex(re.sub(r'\s+','', s))
                encoding = safe_input(translate_text("解码到字符编码") + " (utf-8): ").strip() or "utf-8"
                print(b.decode(encoding))
            except Exception as e:
                print(translate_text("错误") + ":", e)
            pause()
        elif choice == "3":
            s = safe_input(translate_text("输入文本") + ": ")
            encoding = safe_input(translate_text("文本编码") + " (utf-8): ").strip() or "utf-8"
            print(base64.b64encode(s.encode(encoding)).decode())
            pause()
        elif choice == "4":
            s = safe_input(translate_text("输入 base64") + ": ").strip()
            try:
                b = base64.b64decode(s)
                encoding = safe_input(translate_text("解码到字符编码") + " (utf-8): ").strip() or "utf-8"
                print(b.decode(encoding))
            except Exception as e:
                print(translate_text("错误") + ":", e)
            pause()
        elif choice == "5":
            mode = safe_input("u=encode, d=decode: ").strip().lower()
            if mode == "u":
                text = safe_input(translate_text("输入文本") + ": ")
                print(urllib.parse.quote(text, safe=''))
            elif mode == "d":
                text = safe_input(translate_text("输入 URL 编码文本") + ": ")
                print(urllib.parse.unquote(text))
            else:
                print(translate_text("无效"))
            pause()
        elif choice == "0":
            return
        else:
            print(translate_text("无效选项"))
            pause()

def bytes_calc_menu():
    title = translate_text("字节计算器")
    while True:
        print_header(title)
        print("1) " + translate_text("输入字符串并查看字节长度/Hex"))
        print("2) " + translate_text("查看文件大小"))
        print("0) " + translate_text("返回主菜单"))
        
        c = safe_input(translate_text("选择") + ": ").strip()
        
        if c == "1":
            text = safe_input(translate_text("输入字符串") + ": ")
            encoding = safe_input(translate_text("编码") + " (utf-8): ").strip() or "utf-8"
            b = text.encode(encoding)
            print(f"{translate_text('字节长度')}: {len(b)} ({human_size(len(b))})")
            print("Hex:", b.hex())
            pause()
        elif c == "2":
            p = safe_input(translate_text("输入文件路径") + ": ").strip()
            if not Path(p).exists():
                print(translate_text("文件不存在"))
            else:
                s = Path(p).stat().st_size
                print(f"{translate_text('大小')}: {s} bytes ({human_size(s)})")
            pause()
        elif c == "0":
            return
        else:
            print(translate_text("无效"))
            pause()

def hash_menu():
    title = translate_text("哈希计算")
    while True:
        print_header(title)
        print("1) " + translate_text("字符串哈希 (md5/sha1/sha256/sha512)"))
        print("2) " + translate_text("文件哈希"))
        print("0) " + translate_text("返回主菜单"))
        
        c = safe_input(translate_text("选择") + ": ").strip()
        
        if c == "1":
            algo = safe_input(translate_text("选择算法") + " (md5/sha1/sha224/sha256/sha384/sha512): ").strip().lower()
            text = safe_input(translate_text("输入字符串") + ": ")
            b = text.encode('utf-8')
            try:
                h = getattr(hashlib, algo)(b).hexdigest()
                print(h)
            except Exception as e:
                print(translate_text("错误") + ":", e)
            pause()
        elif c == "2":
            filepath = safe_input(translate_text("输入文件路径") + ": ").strip()
            if not Path(filepath).exists():
                print(translate_text("文件不存在"))
                pause()
                continue
            algo = safe_input(translate_text("选择算法") + " (md5/sha1/sha256/...): ").strip().lower()
            try:
                h = getattr(hashlib, algo)()
            except Exception:
                print(translate_text("不支持的算法"))
                pause()
                continue
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk: break
                    h.update(chunk)
            print(h.hexdigest())
            pause()
        elif c == "0":
            return
        else:
            print(translate_text("无效"))
            pause()

def base64_menu():
    title = translate_text("Base64 编解码")
    while True:
        print_header(title)
        print("1) " + translate_text("文本 -> Base64"))
        print("2) " + translate_text("Base64 -> 文本"))
        print("3) " + translate_text("文件 -> Base64 (输出到文件)"))
        print("4) " + translate_text("Base64 -> 文件 (输入 base64 文本, 输出文件)"))
        print("0) " + translate_text("返回主菜单"))
        
        c = safe_input(translate_text("选择") + ": ").strip()
        
        if c == "1":
            text = safe_input(translate_text("输入文本") + ": ")
            encoding = safe_input(translate_text("编码") + " (utf-8): ").strip() or "utf-8"
            print(base64.b64encode(text.encode(encoding)).decode())
            pause()
        elif c == "2":
            text = safe_input(translate_text("输入 base64") + ": ")
            try:
                b = base64.b64decode(text)
                encoding = safe_input(translate_text("编码") + " (utf-8): ").strip() or "utf-8"
                print(b.decode(encoding))
            except Exception as e:
                print(translate_text("错误") + ":", e)
            pause()
        elif c == "3":
            inpath = safe_input(translate_text("输入文件路径") + ": ").strip()
            if not Path(inpath).exists():
                print(translate_text("文件不存在"))
                pause()
                continue
            outpath = safe_input(translate_text("输出文件路径") + " (Base64): ").strip()
            b = Path(inpath).read_bytes()
            Path(outpath).write_text(base64.b64encode(b).decode())
            print(translate_text("写入") + ":", outpath)
            pause()
        elif c == "4":
            text = safe_input(translate_text("输入 base64 文本") + ": ")
            outpath = safe_input(translate_text("输出文件路径") + ": ").strip()
            try:
                Path(outpath).write_bytes(base64.b64decode(text))
                print(translate_text("写入") + ":", outpath)
            except Exception as e:
                print(translate_text("错误") + ":", e)
            pause()
        elif c == "0":
            return
        else:
            print(translate_text("无效"))
            pause()

def img2b64_menu():
    title = translate_text("图片转 Base64")
    print_header(title)
    filepath = safe_input(translate_text("图片文件路径") + ": ").strip()
    
    if not Path(filepath).exists():
        print(translate_text("文件不存在"))
        pause()
        return
    
    b = Path(filepath).read_bytes()
    s = base64.b64encode(b).decode()
    
    is_uri = safe_input(translate_text("是否输出 data URI (y/N)") + ": ").strip().lower() == 'y'
    
    if is_uri:
        ext = Path(filepath).suffix.lower().lstrip(".")
        mimetype = f"image/{ext}" if ext else "application/octet-stream"
        print(f"data:{mimetype};base64,{s}")
    else:
        print(s)
    pause()

def format_menu():
    title = translate_text("格式转换工具")
    while True:
        print_header(title)
        print("1) JSON " + translate_text("美化/压缩"))
        print("2) JavaScript " + translate_text("美化/压缩"))
        print("3) HTML " + translate_text("美化/压缩"))
        print("4) CSS " + translate_text("美化/压缩"))
        print("5) YAML " + translate_text("美化/压缩"))
        print("6) XML " + translate_text("美化/压缩"))
        print("7) 文件格式转换")
        print("0) " + translate_text("返回主菜单"))
        
        c = safe_input(translate_text("选择") + ": ").strip()
        
        if c == "1":
            text = safe_input(translate_text("输入文件路径或粘贴 JSON") + ": ").strip()
            if Path(text).exists():
                text = read_text_from_file(text)
            try:
                obj = json.loads(text)
                mode = safe_input(translate_text("美化") + " (p) " + translate_text("或") + " " + translate_text("压缩") + " (m) ? (p/m): ").strip().lower() or 'p'
                if mode == 'm':
                    print(json.dumps(obj, separators=(',',':'), ensure_ascii=False))
                else:
                    indent = safe_input(translate_text("缩进空格数") + " (2): ").strip()
                    indent = int(indent) if indent.isdigit() else 2
                    print(json.dumps(obj, indent=indent, ensure_ascii=False))
            except Exception as e:
                print("JSON " + translate_text("解析错误") + ":", e)
            pause()
        elif c == "2":
            text = safe_input(translate_text("输入文件路径或粘贴 JavaScript") + ": ").strip()
            if Path(text).exists():
                text = read_text_from_file(text)
            mode = safe_input(translate_text("美化") + " (p) " + translate_text("或") + " " + translate_text("压缩") + " (m) ? (p/m): ").strip().lower() or 'p'
            if mode == 'm':
                import re
                compressed = re.sub(r'\s+', ' ', text).strip()
                print(compressed)
            else:
                print(text.replace(';', ';\n').replace('{', '{\n').replace('}', '\n}'))
            pause()
        elif c == "3":
            text = safe_input(translate_text("输入文件路径或粘贴 HTML") + ": ").strip()
            if Path(text).exists():
                text = read_text_from_file(text)
            mode = safe_input(translate_text("美化") + " (p) " + translate_text("或") + " " + translate_text("压缩") + " (m) ? (p/m): ").strip().lower() or 'p'
            if mode == 'm':
                import re
                compressed = re.sub(r'>\s+<', '><', text)
                compressed = re.sub(r'\s+', ' ', compressed).strip()
                print(compressed)
            else:
                print(text)
            pause()
        elif c == "4":
            text = safe_input(translate_text("输入文件路径或粘贴 CSS") + ": ").strip()
            if Path(text).exists():
                text = read_text_from_file(text)
            mode = safe_input(translate_text("美化") + " (p) " + translate_text("或") + " " + translate_text("压缩") + " (m) ? (p/m): ").strip().lower() or 'p'
            if mode == 'm':
                import re
                compressed = re.sub(r'\s+', ' ', text).strip()
                print(compressed)
            else:
                print(text.replace(';', ';\n').replace('{', '{\n').replace('}', '\n}'))
            pause()
        elif c == "5":
            try:
                import yaml
            except ImportError:
                print("YAML 库未安装，请安装 PyYAML")
                pause()
                continue
            text = safe_input(translate_text("输入文件路径或粘贴 YAML") + ": ").strip()
            if Path(text).exists():
                text = read_text_from_file(text)
            try:
                obj = yaml.safe_load(text)
                mode = safe_input(translate_text("美化") + " (p) " + translate_text("或") + " " + translate_text("压缩") + " (m) ? (p/m): ").strip().lower() or 'p'
                if mode == 'm':
                    print(yaml.dump(obj, default_flow_style=True))
                else:
                    indent = safe_input(translate_text("缩进空格数") + " (2): ").strip()
                    indent = int(indent) if indent.isdigit() else 2
                    print(yaml.dump(obj, default_flow_style=False, indent=indent))
            except Exception as e:
                print("YAML " + translate_text("解析错误") + ":", e)
            pause()
        elif c == "6":
            import xml.etree.ElementTree as ET
            import xml.dom.minidom
            text = safe_input(translate_text("输入文件路径或粘贴 XML") + ": ").strip()
            if Path(text).exists():
                text = read_text_from_file(text)
            try:
                root = ET.fromstring(text)
                mode = safe_input(translate_text("美化") + " (p) " + translate_text("或") + " " + translate_text("压缩") + " (m) ? (p/m): ").strip().lower() or 'p'
                if mode == 'm':
                    print(ET.tostring(root, encoding='unicode'))
                else:
                    rough_string = ET.tostring(root, encoding='unicode')
                    reparsed = xml.dom.minidom.parseString(rough_string)
                    print(reparsed.toprettyxml(indent="  "))
            except Exception as e:
                print("XML " + translate_text("解析错误") + ":", e)
            pause()
        elif c == "7":
            # 文件格式转换
            input_path = safe_input("输入源文件路径: ").strip()
            if not Path(input_path).exists():
                print("文件不存在")
                pause()
                continue
            output_format = safe_input("输入目标格式 (如 png, jpg, pdf): ").strip().lower()
            output_path = safe_input("输入输出文件路径 (包括扩展名): ").strip()
            try:
                if PIL_AVAILABLE and input_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
                    from PIL import Image
                    img = Image.open(input_path)
                    img.save(output_path, output_format.upper())
                    print(f"图像转换完成: {output_path}")
                elif input_path.lower().endswith('.txt') and output_format == 'pdf':
                    # 簡單文本到 PDF，需要 reportlab 或其他
                    try:
                        from reportlab.pdfgen import canvas
                        c = canvas.Canvas(output_path)
                        with open(input_path, 'r', encoding='utf-8') as f:
                            text = f.read()
                        c.drawString(100, 750, text)
                        c.save()
                        print(f"文本转 PDF 完成: {output_path}")
                    except ImportError:
                        print("需要安装 reportlab: pip install reportlab")
                else:
                    print("不支持的格式转换")
            except Exception as e:
                print(f"转换失败: {e}")
            pause()
        elif c == "0":
            return
        else:
            print(translate_text("无效"))
            pause()

def rsa_menu():
    title = "RSA 加密/解密/签名"
    if not CRYPTO_AVAILABLE:
        print(translate_text("错误: cryptography 库未安装"))
        pause()
        return

    while True:
        print_header(title)
        print("1) 生成 RSA 密钥对 (PEM)")
        print("2) 公钥文件加密 (RSA OAEP base64 输出)")
        print("3) 私钥文件解密 (输入 base64)")
        print("4) 私钥签名 (PSS, SHA256, base64 输出)")
        print("5) 公钥验签 (输入 base64 签名)")
        print("0) 返回")

        cmd = safe_input("选择: ").strip()

        if cmd == "1":
            key_size = safe_input("输入密钥长度 (2048/3072/4096, 默认2048): ").strip() or "2048"
            try:
                ks = int(key_size)
            except:
                ks = 2048
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=ks)
            pub = private_key.public_key()

            priv_path = safe_input("保存私钥路径 (.pem): ").strip()
            pub_path = safe_input("保存公钥路径 (.pem): ").strip()
            if priv_path:
                Path(priv_path).write_bytes(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            if pub_path:
                Path(pub_path).write_bytes(pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            print("RSA 密钥对已生成")
            pause()

        elif cmd == "2":
            pub_path = safe_input("输入公钥文件路径 (.pem): ").strip()
            if not Path(pub_path).exists():
                print("文件不存在")
                pause()
                continue
            pub_data = Path(pub_path).read_bytes()
            from cryptography.hazmat.primitives import serialization as _ser
            pubkey = _ser.load_pem_public_key(pub_data)

            plaintext = safe_input("输入要加密的文本 (或输入 @filepath 读取文件): ").strip()
            if plaintext.startswith("@"):
                p = plaintext[1:]
                if Path(p).exists():
                    b = Path(p).read_bytes()
                else:
                    print("文件不存在")
                    pause()
                    continue
            else:
                b = plaintext.encode('utf-8')

            ciphertext = pubkey.encrypt(b, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            out = base64.b64encode(ciphertext).decode()
            print(out)
            pause()

        elif cmd == "3":
            priv_path = safe_input("输入私钥文件路径 (.pem): ").strip()
            if not Path(priv_path).exists():
                print("文件不存在")
                pause()
                continue
            priv_data = Path(priv_path).read_bytes()
            from cryptography.hazmat.primitives import serialization as _ser
            try:
                privkey = _ser.load_pem_private_key(priv_data, password=None)
            except Exception as e:
                print("无法加载私钥:", e)
                pause()
                continue

            ct_b64 = safe_input("输入 base64 密文: ").strip()
            try:
                ct = base64.b64decode(ct_b64)
                pt = privkey.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                try:
                    print(pt.decode('utf-8'))
                except:
                    print(pt)
            except Exception as e:
                print("解密失败:", e)
            pause()

        elif cmd == "4":
            priv_path = safe_input("输入私钥文件路径 (.pem): ").strip()
            if not Path(priv_path).exists():
                print("文件不存在")
                pause()
                continue
            priv_data = Path(priv_path).read_bytes()
            from cryptography.hazmat.primitives import serialization as _ser
            try:
                privkey = _ser.load_pem_private_key(priv_data, password=None)
            except Exception as e:
                print("无法加载私钥:", e)
                pause()
                continue

            msg = safe_input("输入要签名的文本: ").strip().encode('utf-8')
            sig = privkey.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            print(base64.b64encode(sig).decode())
            pause()

        elif cmd == "5":
            pub_path = safe_input("输入公钥文件路径 (.pem): ").strip()
            if not Path(pub_path).exists():
                print("文件不存在")
                pause()
                continue
            pub_data = Path(pub_path).read_bytes()
            from cryptography.hazmat.primitives import serialization as _ser
            pubkey = _ser.load_pem_public_key(pub_data)

            msg = safe_input("输入原文: ").strip().encode('utf-8')
            sig_b64 = safe_input("输入 base64 签名: ").strip()
            try:
                sig = base64.b64decode(sig_b64)
                pubkey.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                print("签名验证: 成功")
            except Exception as e:
                print("签名验证失败:", e)
            pause()

        elif cmd == "0":
            return
        else:
            print("无效选项")
            pause()

def aes_menu():
    title = "AES (AES-GCM) 加密/解密"
    if not CRYPTO_AVAILABLE:
        print(translate_text("错误: cryptography 库未安装"))
        pause()
        return

    while True:
        print_header(title)
        print("1) 生成随机 AES-256 密钥 (Base64)")
        print("2) 使用 AES-GCM 加密 (输出 base64 nonce+ciphertext)")
        print("3) 使用 AES-GCM 解密 (输入 base64 nonce+ciphertext)")
        print("0) 返回")

        cmd = safe_input("选择: ").strip()
        if cmd == "1":
            key = os.urandom(32)
            print(base64.b64encode(key).decode())
            pause()
        elif cmd == "2":
            key_b64 = safe_input("输入 base64 密钥: ").strip()
            try:
                key = base64.b64decode(key_b64)
            except:
                print("无效密钥")
                pause()
                continue

            plaintext = safe_input("输入明文文本 (或 @filepath 读取文件): ").strip()
            if plaintext.startswith("@"):
                p = plaintext[1:]
                if Path(p).exists():
                    data = Path(p).read_bytes()
                else:
                    print("文件不存在")
                    pause()
                    continue
            else:
                data = plaintext.encode('utf-8')

            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, data, associated_data=None)
            out = base64.b64encode(nonce + ct).decode()
            print(out)
            pause()

        elif cmd == "3":
            key_b64 = safe_input("输入 base64 密钥: ").strip()
            try:
                key = base64.b64decode(key_b64)
            except:
                print("无效密钥")
                pause()
                continue

            in_b64 = safe_input("输入 base64 (nonce+ciphertext): ").strip()
            try:
                blob = base64.b64decode(in_b64)
                nonce = blob[:12]
                ct = blob[12:]
                aesgcm = AESGCM(key)
                pt = aesgcm.decrypt(nonce, ct, associated_data=None)
                try:
                    print(pt.decode('utf-8'))
                except:
                    print(pt)
            except Exception as e:
                print("解密失败:", e)
            pause()
        elif cmd == "0":
            return
        else:
            print("无效选项")
            pause()

def sm2_menu():
    title = "国密 SM2 工具"
    if not GMSM_AVAILABLE:
        print("错误: gmssl 库未安装 (SM2 不可用)")
        pause()
        return

    while True:
        print_header(title)
        print("1) 生成随机私钥 (hex)\n   (注意: 公钥需由用户提供或使用其它工具计算)")
        print("2) 使用私钥签名 (hex 私钥与消息)")
        print("3) 使用公钥验签 (hex 公钥与消息与签名)")
        print("4) 使用公钥加密 (hex 公钥 与 消息)")
        print("5) 使用私钥解密 (hex 私钥 与 密文 base64)")
        print("0) 返回")

        cmd = safe_input("选择: ").strip()
        if cmd == "1":
            priv = gmfunc.random_hex(64)
            print(f"私钥(hex): {priv}")
            print("提示: 请使用支持 SM2 的工具从私钥计算公钥 (或手动提供)")
            pause()
        elif cmd == "2":
            priv = safe_input("输入私钥(hex): ").strip()
            msg = safe_input("输入要签名的文本: ").strip()
            try:
                sm2_crypt = sm2.CryptSM2(private_key=priv, public_key='')
                k = gmfunc.random_hex(sm2_crypt.para_len)
                sig = sm2_crypt.sign(msg.encode('utf-8'), k)
                print(f"签名(hex): {sig}")
            except Exception as e:
                print("签名失败:", e)
            pause()
        elif cmd == "3":
            pub = safe_input("输入公钥(hex): ").strip()
            msg = safe_input("输入原文: ").strip()
            sig = safe_input("输入签名(hex): ").strip()
            try:
                sm2_crypt = sm2.CryptSM2(public_key=pub, private_key='')
                ok = sm2_crypt.verify(sig, msg.encode('utf-8'))
                print("验签: ", "成功" if ok else "失败")
            except Exception as e:
                print("验签失败:", e)
            pause()
        elif cmd == "4":
            pub = safe_input("输入公钥(hex): ").strip()
            msg = safe_input("输入要加密的文本: ").strip()
            try:
                sm2_crypt = sm2.CryptSM2(public_key=pub, private_key='')
                ct = sm2_crypt.encrypt(msg.encode('utf-8'))
                print(base64.b64encode(ct).decode())
            except Exception as e:
                print("加密失败:", e)
            pause()
        elif cmd == "5":
            priv = safe_input("输入私钥(hex): ").strip()
            b64 = safe_input("输入密文(base64): ").strip()
            try:
                sm2_crypt = sm2.CryptSM2(private_key=priv, public_key='')
                ct = base64.b64decode(b64)
                pt = sm2_crypt.decrypt(ct)
                try:
                    print(pt.decode('utf-8'))
                except:
                    print(pt)
            except Exception as e:
                print("解密失败:", e)
            pause()
        elif cmd == "0":
            return
        else:
            print("无效选项")
            pause()

def csr_menu():
    """CSR 证书生成和查看菜单"""
    title = translate_text("CSR 证书生成/查看")
    while True:
        print_header(title)
        print("1) " + translate_text("生成 CSR 证书"))
        print("2) " + translate_text("查看 CSR 证书"))
        print("0) " + translate_text("返回主菜单"))
        
        cmd = safe_input(translate_text("选择") + ": ").strip()
        
        if cmd == "1":
            if not CRYPTO_AVAILABLE:
                print(translate_text("错误: cryptography 库未安装"))
                pause()
                continue
            
            print_header(translate_text("生成 CSR 证书"))
            print(translate_text("输入证书信息:"))
            cn = safe_input("Common Name (CN): ").strip()
            org = safe_input("Organization (O): ").strip()
            country = safe_input("Country (C) [CN]: ").strip() or "CN"
            
            if not cn or not org:
                print(translate_text("信息不完整"))
                pause()
                continue
            
            try:
                
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                
                subject = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                ])
                
                csr = x509.CertificateSigningRequestBuilder().subject_name(
                    subject
                ).sign(private_key, hashes.SHA256())
                
                csr_path = safe_input(translate_text("保存 CSR 文件路径") + " (.csr): ").strip()
                key_path = safe_input(translate_text("保存私钥文件路径") + " (.key): ").strip()
                
                if csr_path and key_path:
                    Path(csr_path).write_bytes(csr.public_bytes(serialization.Encoding.PEM))
                    Path(key_path).write_bytes(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                    print(translate_text("CSR 生成成功"))
                    print(f"CSR: {csr_path}")
                    print(f"{translate_text('私钥')}: {key_path}")
            except Exception as e:
                print(translate_text("生成失败") + ":", str(e))
            pause()
        
        elif cmd == "2":
            if not CRYPTO_AVAILABLE:
                print(translate_text("错误: cryptography 库未安装"))
                pause()
                continue
            
            print_header(translate_text("查看 CSR 证书"))
            csr_path = safe_input(translate_text("输入 CSR 文件路径") + ": ").strip()
            
            if not Path(csr_path).exists():
                print(translate_text("文件不存在"))
                pause()
                continue
            
            try:
                csr_data = Path(csr_path).read_bytes()
                csr = x509.load_pem_x509_csr(csr_data)
                
                print(translate_text("CSR 信息:"))
                print(f"{translate_text('主题')}:")
                for attr in csr.subject:
                    print(f"  {attr.oid._name}: {attr.value}")
                print(f"\n{translate_text('公钥算法')}: {csr.public_key().__class__.__name__}")
                print(f"PEM {translate_text('格式')}:")
                print(csr_data.decode())
            except Exception as e:
                print(translate_text("读取失败") + ":", str(e))
            pause()
        
        elif cmd == "0":
            return
        else:
            print(translate_text("无效选项"))
            pause()

def generate_crypto_address():
    """生成真实格式的加密货币地址"""
    if random.choice([True, False]):
        return 'bc1q' + ''.join(random.choices('0123456789acdefghjkmnpqrstuvwxyz', k=39))
    else:
        prefix = random.choice(['1', '3'])
        return prefix + ''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=33))

def show_invasion_animation(animation_type, server_address, card_key, product_name="Unknown", card_count=1, current_card_idx=1, delay_min=0.0, delay_max=0.0):
    """显示入侵卡网动画 - 全英文黑客风格
    animation_type: '1'=魔理沙, '2'=雪碧, '3'=Atri
    server_address: 服务器地址
    card_key: 生成的卡密
    product_name: 商品名
    card_count: 总卡密数量
    current_card_idx: 当前卡密索引
    """
    server_to_animation = {
        'bakamarisa.shop': '1',
        'shop.xuebimc.shop': '2',
        'shop.atrishop.xyz': '3',
        'munan.shop': '4'
    }
    
    animation_names = {
        '1': 'MARISA',
        '2': 'XUEBI',
        '3': 'ATRI',
        '4': 'MUNAN'
    }
    
    if server_address in server_to_animation:
        animation_type = server_to_animation[server_address]
    
    animation_name = animation_names.get(animation_type, 'MARISA')
    
    clear_screen()
    
    if delay_max > 0:
        random_delay = random.uniform(delay_min, delay_max)
        clear_screen()

        def _sleep_random():
            base = 0.02
            jitter = random.uniform(delay_min, delay_max) if (delay_max > 0 or delay_min > 0) else 0.0
            time.sleep(base + jitter)

        print("=" * 60)
        print(f"[SYSTEM] {animation_name} CARD NETWORK INVASION PROTOCOL")
        print(f"[STATUS] Processing card {current_card_idx}/{card_count}")
        print("=" * 60)
        print()

        print(f"[INFO] TARGET PRODUCT: {product_name}")
        print()
        _sleep_random()

        print(f"[*] Establishing connection to: {server_address}")
        print()

        connecting_chars = ['|', '/', '-', '\\']
        for i in range(12):
            print(f"[CONNECT] {connecting_chars[i % 4]}", end='\r')
            _sleep_random()
        print("[CONNECT] ✓ CONNECTION ESTABLISHED")
        print()
        _sleep_random()
        if server_address == 'bakamarisa.shop':
            print("[!] CAPTCHA VERIFICATION REQUIRED")
            print()

            captcha = ''.join(random.choices(string.digits, k=6))
            print(f"[CAPTCHA] {captcha}")
            print()

            print("[*] Running brute-force attack on captcha...")
            print()

            attempts_list = [
                f"[ATTEMPT] {i}: {''.join(random.choices(string.digits, k=6))}"
                for i in range(1, 8)
            ]

            for attempt in attempts_list:
                print(attempt)
                _sleep_random()

            print(f"[SUCCESS] CAPTCHA CRACKED: {captcha}")
            print()
            _sleep_random()

        print("[*] INITIATING CARD DECRYPTION...")
        print()

        for i in range(0, 101, 5):
            filled = int(50 * i / 100)
            bar = "█" * filled + "░" * (50 - filled)
            print(f"[DECRYPT] [{bar}] {i}%")
            _sleep_random()

        print("[DECRYPT] [" + "█" * 50 + "] 100%")
        print()
        print("[✓] DECRYPTION COMPLETE")
        print()
        _sleep_random()

        print("[*] GENERATING AUXILIARY DATA STREAMS...")
        print()

        crypto_addresses = [generate_crypto_address() for _ in range(card_count)]

        print("[CRYPTOCURRENCY_ADDRESSES]")
        for idx, addr in enumerate(crypto_addresses, 1):
            marker = ">>>" if idx == current_card_idx else "   "
            print(f"  {marker} [{idx}] {addr}")
            _sleep_random()

        print()
        print("[*] Performing final validation...")
        print()

        for i in range(20):
            filled = int(50 * i / 20)
            bar = "█" * filled + "░" * (50 - filled)
            print(f"[VALIDATE] [{bar}] {min(100, i*5)}%", end='\r')
            _sleep_random()

        print()
        print("[✓] VALIDATION COMPLETE")
        print()
        _sleep_random()

        print("=" * 60)
        print(f"[✓✓✓] GENERATED CARD KEY [{current_card_idx}/{card_count}]")
        print("=" * 60)
        print()
        print(f">>> {card_key} <<<")
        print()
        print("=" * 60)
        print()

def card_menu():
    """卡密生成器 - 完全重构版本"""
    title = translate_text("卡密生成器")
    
    products = [
        "VapeV4月卡", "VapeV4永久", "VapeLite月卡", "VapeLite永久",
        "DripLite周卡", "DripLite月卡", "DripLite年卡", "DripLite永久",
        "OpaiClient永久", "OpalClient永久", "RiseClient永久", "MyuaClient永久",
        "Breeze永久", "BreezePlus永久", "RyavenClient永久", "Dream月卡",
        "Dream永久", "DreamPro月卡", "DreamPro永久", "AlisaClient永久",
        "AlisaClient月卡", "AlisaClient周卡", "AlisaClient天卡", "AugustusClient永久",
        "Slinky永久", "Rose月卡", "Rose永久", "Zen周卡", "Edge永久",
        "Apple周卡", "Apple月卡", "Apple永久","MinecraftUnBan1","MinecraftUnBan20"
    ]
    
    card_format_templates = {
        '1': {'name': '魔理沙', 'format': 'marisa-{card}', 'card_format': '6-8', 'card_sep': '', 'desc': 'marisa-XXXXX-XXXXXXXX'},
        '2': {'name': 'UUID', 'format': '{card}', 'card_format': '8-4-4-4-12', 'card_sep': '-', 'desc': 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'},
        '3': {'name': 'Drip', 'format': '{card}', 'card_format': '3-20', 'card_sep': '-', 'desc': 'DRP-XXXXXXXXXXXXXXXX'},
        '4': {'name': 'MinecraftUnBanNFA1+', 'format': '[Microsoft_Hit][MC][unban][1]{card}', 'card_format': '无', 'card_sep': '', 'desc': '[Microsoft_Hit][MC][unban][1]example@email.com:password123'},
        '5': {'name': 'MinecraftUnBanNFA20+', 'format': '[Microsoft_Hit][MC][unban][20]{card}', 'card_format': '无', 'card_sep': '', 'desc': '[Microsoft_Hit][MC][unban][20]example@email.com:password123'},
        '6': {'name': '雪碧', 'format': 'XUEBI-{card}', 'card_format': '5-18', 'card_sep': '', 'desc': 'XUEBI-XXXXXXXXXXXXXXXXXX'},
        '0': {'name': '自定义格式', 'format': 'custom', 'card_format': '8-4-4-4-12', 'card_sep': '-', 'desc': 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'}
    }
    
    def get_minecraft_account(account_type):
        """获取随机生成的微软账号"""
        return generate_minecraft_account(account_type)
    
    config = {
        
        'card_format_template': '0',
        
        'group_by_product': True,
        'show_product_info': True,
        'product_only_at_start': True,
        'line_break_mode': '1',  
        'product_as_prefix': False,
        'selected_product': "随机选择",
        'auto_format_detect': True,  
        'show_order_label': True,  
        'show_card_label': True,  
        
        'hide_product_name': False,
        'hide_order_number': False,
        'hide_card_key': False,
        
        'order_year': True,
        'order_month': True,
        'order_day': True,
        'order_hour': True,
        'order_minute': True,
        'order_second': True,
        'order_random_len': 6,
        'order_digits_only': False,
        'order_separator': '',
        
        'card_format': "8-4-4-4-12",
        'card_separator': '-',
        'card_digits_only': False,
        'card_letters_only': False,
        'card_letters_case': "upper",
        'product_prefix_separator': '-',
        
        'count': 1,
        
        'enable_invasion_animation': False,
        'animation_type': '1',  
        'server_address': 'bakamarisa.shop',  
        'animation_delay_min': 0.0,
        'animation_delay_max': 0.0,
    }
    
    def generate_advanced_order(cfg):
        """生成高级订单号"""
        now = datetime.now()
        parts = []
        
        if cfg['order_year']: parts.append(now.strftime("%Y"))
        if cfg['order_month']: parts.append(now.strftime("%m"))
        if cfg['order_day']: parts.append(now.strftime("%d"))
        if cfg['order_hour']: parts.append(now.strftime("%H"))
        if cfg['order_minute']: parts.append(now.strftime("%M"))
        if cfg['order_second']: parts.append(now.strftime("%S"))
        
        rand_len = cfg['order_random_len']
        if cfg['order_digits_only']:
            random_part = ''.join(random.choices(string.digits, k=rand_len))
        else:
            random_part = ''.join(random.choices(string.ascii_letters + string.digits, k=rand_len))
        
        parts.append(random_part)
        order_id = cfg['order_separator'].join(parts) if cfg['order_separator'] else ''.join(parts)
        
        return order_id.upper()
    
    def detect_format_by_product(product_name):
        """根据商品名检测格式"""
        if 'MinecraftUnBan1' in product_name:
            return '4'  
        elif 'MinecraftUnBan20' in product_name:
            return '5'  
        elif 'Drip' in product_name:
            return '3'  
        return None
    
    def get_filtered_products_for_template(template_id):
        """根据格式模板过滤商品列表"""
        if template_id == '3':  
            return [p for p in products if 'Drip' in p]
        elif template_id == '4':  
            return [p for p in products if 'MinecraftUnBan1' in p]
        elif template_id == '5':  
            return [p for p in products if 'MinecraftUnBan20' in p]
        return products
    
    def generate_advanced_card(cfg, is_drip_format=False):
        """生成高级卡密"""
        if cfg['card_format'] == '无':
            return ''
        
        format_parts = cfg['card_format'].split('-')
        lengths = [int(x) for x in format_parts if x.isdigit()]
        
        if cfg['card_digits_only']:
            charset = string.digits
        elif cfg['card_letters_only']:
            charset = string.ascii_letters
        else:
            charset = string.ascii_letters + string.digits
        
        parts = []
        for i, length in enumerate(lengths):
            
            if is_drip_format and i == 0:
                part = 'DRP'
            else:
                if cfg['card_letters_case'] == "upper":
                    part = ''.join(random.choices(charset.upper(), k=length))
                elif cfg['card_letters_case'] == "lower":
                    part = ''.join(random.choices(charset.lower(), k=length))
                else:
                    part = ''.join(random.choices(charset, k=length))
            parts.append(part)
        
        card_code = cfg['card_separator'].join(parts)
        return card_code
    
    line_break_modes = {'1': '每条数据换行', '2': '商品后换行', '3': '不换行'}
    
    while True:
        print_header(title)
        print(translate_text("当前设置:"))
        print(f"  1) {translate_text('卡密格式模板')}: {card_format_templates[config['card_format_template']]['name']}")
        print()
        print("  [基础设置]")
        print(f"  2) 按商品分组输出: {config['group_by_product']}")
        print(f"  3) 显示商品信息: {config['show_product_info']}")
        print(f"  3.5) 商品只在开头显示: {config['product_only_at_start']}")
        print(f"  4) 换行模式: {line_break_modes[config['line_break_mode']]}")
        print(f"  5) 商品名作为卡密前缀: {config['product_as_prefix']}")
        print(f"  6) 自动检测格式: {config['auto_format_detect']}")
        print(f"  7) 显示订单号标签: {config['show_order_label']}")
        print(f"  8) 显示卡密标签: {config['show_card_label']}")
        print(f"  9) 选择商品: {config['selected_product']}")
        print()
        print("  [隐藏设置]")
        print(f"  9.1) 隐藏商品名: {config['hide_product_name']}")
        print(f"  9.2) 隐藏订单号: {config['hide_order_number']}")
        print(f"  9.3) 隐藏卡密: {config['hide_card_key']}")
        print()
        print("  [订单号设置]")
        print(f"  10) 订单号格式: 年{config['order_year']} 月{config['order_month']} 日{config['order_day']}")
        print(f"  11) 订单号格式: 时{config['order_hour']} 分{config['order_minute']} 秒{config['order_second']}")
        print(f"  12) 订单号随机部分长度: {config['order_random_len']}")
        print(f"  13) 订单号只使用数字: {config['order_digits_only']}")
        print(f"  14) 订单号分隔符: {repr(config['order_separator'])}")
        print()
        print("  [卡密设置]")
        
        current_template = card_format_templates.get(config['card_format_template'], {})
        template_card_format = current_template.get('card_format', config['card_format'])
        template_card_sep = current_template.get('card_sep', config['card_separator'])
        print(f"  15) 卡密格式: {template_card_format}")
        print(f"  16) 卡密分隔符: {repr(template_card_sep)}")
        print(f"  17) 卡密字符: 数字{config['card_digits_only']} 字母{config['card_letters_only']}")
        print(f"  18) 卡密字母大小写: {config['card_letters_case']}")
        print(f"  19) 商品前缀分隔符: {repr(config['product_prefix_separator'])}")
        print()
        print(f"  20) 生成数量: {config['count']}")
        print(f"  21) 启用入侵卡网动画: {config['enable_invasion_animation']}")
        print(f"  21.5) 动画随机延迟: {config['animation_delay_min']:.1f}s ~ {config['animation_delay_max']:.1f}s")
        
        animation_display = ['魔理沙', '雪碧', 'Atri', '木南'][int(config['animation_type'])-1] if config['animation_type'] in ['1','2','3','4'] else '魔理沙'
        print(f"  22) 选择服务器/动画: {config['server_address']} ({animation_display})")
        print(f"  23) 生成卡密")
        print("  0) " + translate_text("返回主菜单"))
        print()
        
        cmd = safe_input(translate_text("选择") + " (1-23/0): ").strip()
        
        if cmd == "1":
            
            print_header(translate_text("选择卡密格式模板"))
            for key in sorted(card_format_templates.keys(), key=lambda x: (x != '0', x)):
                template = card_format_templates[key]
                print(f"{key}) {template['name']}")
                print(f"   示例: {template['desc']}")
            choice = safe_input(translate_text("选择") + ": ").strip()
            if choice in card_format_templates:
                config['card_format_template'] = choice
                template = card_format_templates[choice]
                if choice != '0':  
                    config['card_format'] = template['card_format']
                    config['card_separator'] = template['card_sep']
                    
                    filtered_prods = get_filtered_products_for_template(choice)
                    if filtered_prods and choice in ['3', '4', '5']:
                        config['selected_product'] = filtered_prods[0]
            pause()
        elif cmd == "2":
            config['group_by_product'] = not config['group_by_product']
        elif cmd == "3":
            config['show_product_info'] = not config['show_product_info']
        elif cmd == "3.5":
            config['product_only_at_start'] = not config['product_only_at_start']
        elif cmd == "4":
            print_header(translate_text("选择换行模式"))
            print("1) 每条数据换行 (商品 X\\n订单号 X\\n卡密 X)")
            print("2) 商品后换行 (商品 X\\n订单号 X  卡密 X)")
            print("3) 不换行 (商品 X  订单号 X  卡密 X)")
            choice = safe_input(translate_text("选择") + " (1/2/3): ").strip()
            if choice in ['1', '2', '3']:
                config['line_break_mode'] = choice
            pause()
        elif cmd == "5":
            config['product_as_prefix'] = not config['product_as_prefix']
        elif cmd == "6":
            config['auto_format_detect'] = not config['auto_format_detect']
        elif cmd == "7":
            config['show_order_label'] = not config['show_order_label']
        elif cmd == "8":
            config['show_card_label'] = not config['show_card_label']
        elif cmd == "9":
            print_header(translate_text("选择商品"))
            
            filtered_prods = get_filtered_products_for_template(config['card_format_template'])
            for i, prod in enumerate(filtered_prods, 1):
                print(f"{i}) {prod}")
            print(f"{len(filtered_prods)+1}) 随机选择")
            choice = safe_input(translate_text("选择") + ": ").strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(filtered_prods):
                    config['selected_product'] = filtered_prods[idx]
                elif idx == len(filtered_prods):
                    config['selected_product'] = "随机选择"
            except:
                pass
            pause()
        elif cmd == "9.1":
            config['hide_product_name'] = not config['hide_product_name']
        elif cmd == "9.2":
            config['hide_order_number'] = not config['hide_order_number']
        elif cmd == "9.3":
            config['hide_card_key'] = not config['hide_card_key']
        elif cmd == "10":
            config['order_year'] = not config['order_year']
            config['order_month'] = not config['order_month']
            config['order_day'] = not config['order_day']
        elif cmd == "11":
            config['order_hour'] = not config['order_hour']
            config['order_minute'] = not config['order_minute']
            config['order_second'] = not config['order_second']
        elif cmd == "12":
            n = safe_input(translate_text("输入随机部分长度") + " (1-20): ").strip()
            try:
                config['order_random_len'] = max(1, min(20, int(n)))
            except:
                print(translate_text("无效数字"))
            pause()
        elif cmd == "13":
            config['order_digits_only'] = not config['order_digits_only']
        elif cmd == "14":
            sep = safe_input(translate_text("输入订单号分隔符") + " (留空为无): ").strip()
            config['order_separator'] = sep
        elif cmd == "15":
            fmt = safe_input(translate_text("输入卡密格式") + " (如 8-4-4-4-12): ").strip()
            if fmt and all(part.isdigit() for part in fmt.split('-')):
                config['card_format'] = fmt
            else:
                print(translate_text("格式无效"))
                pause()
        elif cmd == "16":
            sep = safe_input(translate_text("输入卡密分隔符") + ": ").strip()
            config['card_separator'] = sep if sep else '-'
        elif cmd == "17":
            mode = safe_input(translate_text("输入模式") + " (0=混合/1=数字/2=字母): ").strip()
            if mode == "1":
                config['card_digits_only'] = True
                config['card_letters_only'] = False
            elif mode == "2":
                config['card_digits_only'] = False
                config['card_letters_only'] = True
            else:
                config['card_digits_only'] = False
                config['card_letters_only'] = False
            pause()
        elif cmd == "18":
            mode = safe_input(translate_text("选择") + " (upper/lower/mixed): ").strip().lower()
            if mode in ['upper', 'lower', 'mixed']:
                config['card_letters_case'] = mode
            pause()
        elif cmd == "19":
            sep = safe_input(translate_text("输入商品前缀分隔符") + ": ").strip()
            config['product_prefix_separator'] = sep if sep else '-'
        elif cmd == "20":
            n = safe_input(translate_text("输入生成数量") + " (1-10000): ").strip()
            try:
                config['count'] = max(1, min(10000, int(n)))
            except:
                print(translate_text("无效数字"))
                pause()
        elif cmd == "21":
            config['enable_invasion_animation'] = not config['enable_invasion_animation']
        elif cmd == "21.5":
            min_delay = safe_input("输入最小延迟（秒，如0.0）: ").strip()
            max_delay = safe_input("输入最大延迟（秒，如0.5）: ").strip()
            try:
                min_d = float(min_delay)
                max_d = float(max_delay)
                if min_d <= max_d:
                    config['animation_delay_min'] = min_d
                    config['animation_delay_max'] = max_d
                else:
                    print("最小延迟不能大于最大延迟")
            except:
                print("无效数字")
            pause()
        elif cmd == "22":
            print_header(translate_text("选择服务器和动画类型"))
            servers = [
                ('bakamarisa.shop', '1', '魔理沙'),
                ('shop.xuebimc.shop', '2', '雪碧'),
                ('shop.atrishop.xyz', '3', 'Atri'),
                ('munan.shop', '4', '木南')
            ]
            for i, (server, anim_type, anim_name) in enumerate(servers, 1):
                print(f"{i}) {server} ({anim_name})")
            choice = safe_input(translate_text("选择") + " (1-4): ").strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(servers):
                    server_addr, anim_type, anim_name = servers[idx]
                    config['server_address'] = server_addr
                    config['animation_type'] = anim_type
            except:
                pass
            pause()
        elif cmd == "23":
            print_header(translate_text("生成结果"))
            
            def format_output(prod, order_id, full_card, is_minecraft=False, show_product=True):
                """格式化输出根据换行模式，支持隐藏功能"""
                if is_minecraft:
                    if config['hide_card_key']:
                        return "[Microsoft_Hit][MC][unban][已隐藏]"
                    return full_card
                
                prod_display = "****" if config['hide_product_name'] else prod
                order_display = "****" if config['hide_order_number'] else order_id
                card_display = "****" if config['hide_card_key'] else full_card
                
                order_label = "订单号" if config['show_order_label'] else ""
                card_label = "卡密" if config['show_card_label'] else ""
                mode = config['line_break_mode']
                
                if mode == '1':  
                    if order_label:
                        line1 = f"{order_label} {order_display}"
                    else:
                        line1 = order_display
                    if card_label:
                        line2 = f"{card_label} {card_display}"
                    else:
                        line2 = card_display
                    return f"{line1}\n{line2}"
                elif mode == '2':  
                    if order_label and card_label:
                        return f"{order_label} {order_display}  {card_label} {card_display}"
                    elif order_label:
                        return f"{order_label} {order_display}  {card_display}"
                    elif card_label:
                        return f"{order_display}  {card_label} {card_display}"
                    else:
                        return f"{order_display}  {card_display}"
                else:  
                    parts = []
                    if show_product and order_label and card_label:
                        parts.append(f"商品 {prod_display}  {order_label} {order_display}  {card_label} {card_display}")
                    elif show_product and order_label:
                        parts.append(f"商品 {prod_display}  {order_label} {order_display}  {card_display}")
                    elif show_product and card_label:
                        parts.append(f"商品 {prod_display}  {order_display}  {card_label} {card_display}")
                    elif show_product:
                        parts.append(f"商品 {prod_display}  {order_display}  {card_display}")
                    elif order_label and card_label:
                        parts.append(f"{order_label} {order_display}  {card_label} {card_display}")
                    elif order_label:
                        parts.append(f"{order_label} {order_display}  {card_display}")
                    elif card_label:
                        parts.append(f"{order_display}  {card_label} {card_display}")
                    else:
                        parts.append(f"{order_display}  {card_display}")
                    return parts[0] if parts else f"{order_display}  {card_display}"
            
            def apply_template_format(card_code, template_id):
                """应用模板格式到卡密"""
                template = card_format_templates.get(template_id, {})
                format_str = template.get('format', '{card}')
                
                if template_id in ['4', '5']:
                    return format_str.format(card=card_code)
                
                if format_str == 'custom':
                    return card_code
                return format_str.format(card=card_code)
            
            selected = config['selected_product']
            prods = products if selected == "随机选择" else [selected]
            current_template = config['card_format_template']
            template_config = card_format_templates.get(current_template, {})
            template_card_format = template_config.get('card_format', config['card_format'])
            template_card_sep = template_config.get('card_sep', config['card_separator'])
            gen_config = config.copy()
            gen_config['card_format'] = template_card_format
            gen_config['card_separator'] = template_card_sep
            if config['auto_format_detect'] and selected != "随机选择":
                detected = detect_format_by_product(selected)
                if detected:
                    current_template = detected
            all_cards = []
            for i in range(config['count']):
                prod = random.choice(prods) if selected == "随机选择" else selected
                order_id = generate_advanced_order(config)    
                if 'MinecraftUnBan1' in prod or 'MinecraftUnBan20' in prod:
                    if 'MinecraftUnBan1' in prod:
                        account = get_minecraft_account('4')
                        if account:
                            account_info = f"{account['email']}:{account['password']}|McName:{account['name']}[Hypixel:{account['level']}][Capes:{account['capes']}]"
                            full_card = f"[Microsoft_Hit][MC][unban][1]{account_info}"
                        else:
                            full_card = "[Microsoft_Hit][MC][unban][1]failed_to_generate"
                    else:
                        account = get_minecraft_account('5')
                        if account:
                            account_info = f"{account['email']}:{account['password']}|McName:{account['name']}[Hypixel:{account['level']}][Capes:{account['capes']}]"
                            full_card = f"[Microsoft_Hit][MC][unban][20]{account_info}"
                        else:
                            full_card = "[Microsoft_Hit][MC][unban][20]failed_to_generate"
                    card_code = full_card
                else:
                    card_code = generate_advanced_card(gen_config)
                    card_code = apply_template_format(card_code, current_template)
                    
                    if config['product_as_prefix']:
                        full_card = prod + config['product_prefix_separator'] + card_code
                    else:
                        full_card = card_code       
                all_cards.append((prod, order_id, full_card, card_code))
            if config['enable_invasion_animation']:
                total_cards = len(all_cards)
                for idx, (prod, order_id, full_card, card_code) in enumerate(all_cards):
                    show_invasion_animation(
                        config['animation_type'],
                        config['server_address'],
                        full_card,
                        prod,
                        total_cards,
                        idx + 1,
                        config['animation_delay_min'],
                        config['animation_delay_max']
                    )
                print_header(translate_text("生成结果"))
                if config['group_by_product']:
                    grouped_data = {}
                    for prod, order_id, full_card, card_code in all_cards:
                        if prod not in grouped_data:
                            grouped_data[prod] = []
                        grouped_data[prod].append((order_id, full_card))
                    
                    for prod in prods:
                        if prod in grouped_data and grouped_data[prod]:
                            if config['show_product_info'] and not config['product_only_at_start']:
                                print("")
                                print(f"商品 {prod}")
                                print("")
                            elif config['show_product_info'] and config['product_only_at_start']:
                                print("")
                                print(f"商品 {prod}")
                                print("")
                            for idx, (order_id, full_card) in enumerate(grouped_data[prod]):
                                is_minecraft = 'MinecraftUnBan' in prod
                                # 只在第一条显示商品名（不换行模式）
                                show_prod = (idx == 0) and config['show_product_info'] and config['product_only_at_start'] and config['line_break_mode'] == '3'
                                output = format_output(prod, order_id, full_card, is_minecraft=is_minecraft, show_product=show_prod)
                                print(output)
                                if config['line_break_mode'] in ['1', '2'] and idx < len(grouped_data[prod]) - 1:
                                    print()
                else:
                    for idx, (prod, order_id, full_card, card_code) in enumerate(all_cards):
                        # 只在第一行显示商品名
                        if idx == 0 and config['show_product_info']:
                            print(f"商品 {prod}")
                            print()
                        is_minecraft = 'MinecraftUnBan' in prod
                        # 不换行模式下，商品只在开头显示
                        show_prod = False
                        output = format_output(prod, order_id, full_card, is_minecraft=is_minecraft, show_product=show_prod)
                        print(output)
                        if config['line_break_mode'] in ['1', '2'] and idx < len(all_cards) - 1:
                            print()
            else:
                if config['group_by_product']:
                    grouped_data = {}
                    for prod, order_id, full_card, card_code in all_cards:
                        if prod not in grouped_data:
                            grouped_data[prod] = []
                        grouped_data[prod].append((order_id, full_card))
                    
                    for prod in prods:
                        if prod in grouped_data and grouped_data[prod]:
                            if config['show_product_info'] and not config['product_only_at_start']:
                                print("")
                                print(f"商品 {prod}")
                                print("")
                            elif config['show_product_info'] and config['product_only_at_start']:
                                print("")
                                print(f"商品 {prod}")
                                print("")
                            for idx, (order_id, full_card) in enumerate(grouped_data[prod]):
                                is_minecraft = 'MinecraftUnBan' in prod
                                # 只在第一条显示商品名（不换行模式）
                                show_prod = (idx == 0) and config['show_product_info'] and config['product_only_at_start'] and config['line_break_mode'] == '3'
                                output = format_output(prod, order_id, full_card, is_minecraft=is_minecraft, show_product=show_prod)
                                print(output)
                                if config['line_break_mode'] in ['1', '2'] and idx < len(grouped_data[prod]) - 1:
                                    print()
                else:
                    for idx, (prod, order_id, full_card, card_code) in enumerate(all_cards):
                        # 只在第一行显示商品名
                        if idx == 0 and config['show_product_info']:
                            print(f"商品 {prod}")
                            print()
                        is_minecraft = 'MinecraftUnBan' in prod
                        # 不换行模式下，商品只在开头显示
                        show_prod = False
                        output = format_output(prod, order_id, full_card, is_minecraft=is_minecraft, show_product=show_prod)
                        print(output)
                        if config['line_break_mode'] in ['1', '2'] and idx < len(all_cards) - 1:
                            print()
            
            pause()
        elif cmd == "0":
            return
        else:
            print(translate_text("无效选项"))
            pause()

def hwid_generator_menu():
    title = translate_text("HWID 生成器")
    while True:
        print_header(title)
        print("1) " + translate_text("生成 HWID"))
        print("0) " + translate_text("返回主菜单"))
        
        choice = safe_input(translate_text("选择序号") + ": ").strip()
        
        if choice == "1":
            format_type = safe_input(translate_text("请选择 HWID 格式 (default/compact/dashed): ")).strip().lower()
            try:
                hwid = generate_hwid(format_type)
                print(f"生成的 HWID: {hwid}")
            except ValueError as e:
                print(translate_text("错误") + ":", e)
            pause()
        elif choice == "0":
            return
        else:
            print(translate_text("无效选项"))
            pause()

def manga_image_generator_menu():
    """漫畫圖片生成器 - A4模板排版"""
    title = translate_text("漫畫圖片生成")
    
    if not PIL_AVAILABLE:
        print_header(title)
        print(translate_text("错误: PIL/Pillow 库未安装"))
        print(translate_text("请运行: pip install Pillow"))
        pause()
        return
    
    while True:
        print_header(title)
        print("1) " + translate_text("开始生成漫畫 A4 模板"))
        print("0) " + translate_text("返回主菜单"))
        
        choice = safe_input(translate_text("选择序号") + ": ").strip()
        
        if choice == "1":
            print_header(title)
            
            # 输入源文件夹
            source_folder = safe_input(translate_text("输入漫画图片文件夹路径") + ": ").strip()
            source_path = Path(source_folder)
            
            if not source_path.exists() or not source_path.is_dir():
                print(translate_text("文件夹不存在"))
                pause()
                continue
            
            # 获取所有图片文件
            image_extensions = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp'}
            image_files = sorted([
                f for f in source_path.iterdir() 
                if f.suffix.lower() in image_extensions
            ])
            
            if not image_files:
                print(translate_text("文件夹中没有找到图片"))
                pause()
                continue
            
            print(f"\n{translate_text('找到')} {len(image_files)} {translate_text('张图片')}")
            for i, img_file in enumerate(image_files, 1):
                print(f"  {i}. {img_file.name}")
            
            # 选择输出格式
            print("\n" + translate_text("选择输出格式:"))
            print("1) A4 横向 (297mm × 210mm)")
            print("2) A4 纵向 (210mm × 297mm)")
            
            format_choice = safe_input(translate_text("选择") + " (1/2): ").strip()
            
            # A4尺寸配置 (72 DPI)
            if format_choice == "1":
                a4_width, a4_height = 1122, 794  # A4横向 (72 DPI)
                orientation = "landscape"
            else:
                a4_width, a4_height = 794, 1122  # A4纵向 (72 DPI)
                orientation = "portrait"
            
            # 输出文件夹
            output_folder = safe_input(translate_text("输入输出文件夹路径") + ": ").strip()
            output_path = Path(output_folder)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # 生成A4模板
            manga_generate_a4_templates(image_files, output_path, a4_width, a4_height, orientation)
            
            print(translate_text("\n生成完成！"))
            pause()
        elif choice == "0":
            return
        else:
            print(translate_text("无效选项"))
            pause()

def manga_generate_a4_templates(image_files, output_path, a4_width, a4_height, orientation):
    """
    生成A4模板，每个A4页面放2张图片，按照A3小冊子方式排列
    00001反: 封面 + 后封面
    00001正: 第1页 + 最后一页
    00002反: 第2页 + 倒数第2页
    etc.
    """
    total_images = len(image_files)
    
    # 计算需要的页数（每个A4放2张图片，共两列）
    pages_needed = (total_images + 3) // 4  # 4张图片为一套（2正2反）
    
    print(f"\n{translate_text('开始处理')} {total_images} {translate_text('张图片')}...")
    print(f"{translate_text('输出页数')}: {pages_needed * 2} ({pages_needed} {translate_text('套')}正反)")
    
    # 加载所有图片
    images = []
    for img_file in image_files:
        try:
            img = Image.open(img_file)
            # 转换为RGB（处理RGBA或其他格式）
            if img.mode != 'RGB':
                img = img.convert('RGB')
            images.append((img, img_file.name))
        except Exception as e:
            print(f"{translate_text('警告')}: {img_file.name} - {str(e)}")
    
    if not images:
        print(translate_text("无法加载任何图片"))
        return
    
    # 按照A3小冊子排列逻辑
    # 第一套（00001）: 
    #   反面：图片0（封面）+ 图片最后一张（后封面）
    #   正面：图片1 + 倒数第二张
    # 第二套（00002）:
    #   反面：图片2 + 倒数第三张
    #   正面：图片3 + 倒数第四张
    # etc.
    
    page_num = 1
    front_idx = 0  # 从前往后
    back_idx = len(images) - 1  # 从后往前
    
    while front_idx <= back_idx:
        # 当前套的4张图片
        # 反面: front_idx(左), back_idx(右)
        # 正面: front_idx+1(左), back_idx-1(右)
        
        img1 = images[front_idx] if front_idx <= back_idx else None
        img4 = images[back_idx] if front_idx <= back_idx else None
        img2 = images[front_idx + 1] if front_idx + 1 <= back_idx else None
        img3 = images[back_idx - 1] if front_idx + 1 <= back_idx else None
        
        # 生成反面（包含2张图片，左右交换）
        a4_back = manga_create_a4_double_page(img1, img4, a4_width, a4_height, orientation, flip=True)
        back_filename = f"{page_num:05d}反.png"
        a4_back.save(output_path / back_filename)
        img1_name = img1[1] if img1 else "空白"
        img4_name = img4[1] if img4 else "空白"
        print(f"  ✓ {back_filename} ({img4_name} + {img1_name}) [左右交换]")
        
        # 生成正面（包含2张图片，不交换）
        a4_front = manga_create_a4_double_page(img2, img3, a4_width, a4_height, orientation, flip=False)
        front_filename = f"{page_num:05d}正.png"
        a4_front.save(output_path / front_filename)
        img2_name = img2[1] if img2 else "空白"
        img3_name = img3[1] if img3 else "空白"
        print(f"  ✓ {front_filename} ({img2_name} + {img3_name})")
        
        front_idx += 2
        back_idx -= 2
        page_num += 1

def manga_create_a4_page(image, a4_width, a4_height, orientation):
    """
    创建A4模板页面，将图片放入其中
    按照图片的原始比例缩放并居中放置
    """
    # 创建白色背景的A4页面
    a4_page = Image.new('RGB', (a4_width, a4_height), (255, 255, 255))
    
    # 计算图片缩放尺寸（保持宽高比）
    img_width, img_height = image.size
    img_ratio = img_width / img_height
    
    # A4的可用区域（留一些边距）
    margin = 20
    available_width = a4_width - 2 * margin
    available_height = a4_height - 2 * margin
    available_ratio = available_width / available_height
    
    if img_ratio > available_ratio:
        # 图片较宽，按宽度缩放
        new_width = available_width
        new_height = int(available_width / img_ratio)
    else:
        # 图片较高，按高度缩放
        new_height = available_height
        new_width = int(available_height * img_ratio)
    
    # 缩放图片
    resized_img = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
    
    # 计算居中位置
    x = (a4_width - new_width) // 2
    y = (a4_height - new_height) // 2
    
    # 将缩放后的图片粘贴到A4页面
    a4_page.paste(resized_img, (x, y))
    
    return a4_page

def manga_create_a4_double_page(img_data_left, img_data_right, a4_width, a4_height, orientation, flip=False):
    """
    创建A4模板页面，将两张图片分别放在左右两侧
    img_data: (image_object, filename) 或 None
    flip: 如果为True，交换左右位置（用于"反"面）
    """
    # 创建白色背景的A4页面
    a4_page = Image.new('RGB', (a4_width, a4_height), (255, 255, 255))
    
    # 两列的宽度和高度
    margin_vertical = 10
    margin_horizontal = 10
    margin_between = 10  # 中间间距
    
    col_width = (a4_width - 3 * margin_horizontal - margin_between) // 2
    col_height = a4_height - 2 * margin_vertical
    
    # 如果flip=True，交换左右图片
    if flip:
        img_data_left, img_data_right = img_data_right, img_data_left
    
    # 处理左侧图片
    if img_data_left:
        image_left, _ = img_data_left
        resized_left = manga_resize_to_fit(image_left, col_width, col_height)
        x_left = margin_horizontal + (col_width - resized_left.width) // 2
        y_left = margin_vertical + (col_height - resized_left.height) // 2
        a4_page.paste(resized_left, (x_left, y_left))
    
    # 处理右侧图片
    if img_data_right:
        image_right, _ = img_data_right
        resized_right = manga_resize_to_fit(image_right, col_width, col_height)
        x_right = margin_horizontal + col_width + margin_between + (col_width - resized_right.width) // 2
        y_right = margin_vertical + (col_height - resized_right.height) // 2
        a4_page.paste(resized_right, (x_right, y_right))
    
    return a4_page

def manga_resize_to_fit(image, max_width, max_height):
    """
    按照宽高比缩放图片以适应指定尺寸
    """
    img_width, img_height = image.size
    img_ratio = img_width / img_height
    available_ratio = max_width / max_height
    
    if img_ratio > available_ratio:
        # 图片较宽
        new_width = max_width
        new_height = int(max_width / img_ratio)
    else:
        # 图片较高
        new_height = max_height
        new_width = int(max_height * img_ratio)
    
    return image.resize((new_width, new_height), Image.Resampling.LANCZOS)


def generate_hwid(format_type="default"):
    """HWID生成器，支持多種格式"""
    if format_type == "default":
        return "-".join(["".join(random.choices(string.ascii_uppercase + string.digits, k=4)) for _ in range(4)])
    elif format_type == "compact":
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
    elif format_type == "dashed":
        return "-".join(["".join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(2)])
    else:
        raise ValueError("Unsupported format type")

def generate_card_key():
    """生成隨機卡密"""
    return "".join(random.choices(string.ascii_letters + string.digits, k=16))

def display_animation(animation_type):
    """顯示動畫效果"""
    if animation_type == "marisa":
        print("進入魔理沙伺服器...")
    elif animation_type == "xuebi":
        print("進入雪碧伺服器...")
    elif animation_type == "atri":
        print("進入Atri伺服器...")
    else:
        print("進入伺服器...")

    print("正在破解...")
    for i in range(1, 101):
        time.sleep(0.05)
        print(f"破解進度: {i}%", end="\r")

    print("\n生成隨機二維碼和加密貨幣代碼...")
    crypto_code = "CRYPTO-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=12))
    print(f"二維碼: {qr_code}")
    print(f"加密貨幣代碼: {crypto_code}")

def generate_card_with_animation(server):
    """生成卡密並顯示動畫"""
    if server == "bakamarisa.shop":
        if random.choice([True, False]):
            input("請輸入驗證碼: ")

    animation_type = "marisa" if "marisa" in server else "xuebi" if "xuebimc" in server else "atri" if "atri" in server else "default"
    display_animation(animation_type)

    card_key = generate_card_key()
    print(f"生成的卡密: {card_key}")
def barcode_menu():
    while True:
        print_header("二维码生成工具")
        print("1) 生成 QR 码")
        print("2) 生成条形码 (1D)")
        print("0) 返回")
        choice = safe_input("选择序号: ").strip()
        if choice == "1":
            if not QRCODE_AVAILABLE:
                print("qrcode 库未安装")
                pause()
                continue
            data = safe_input("输入要编码的数据: ")
            if data:
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(data)
                qr.make(fit=True)
                img = qr.make_image(fill='black', back_color='white')
                filename = safe_input("输入文件名 (不含扩展名): ")
                if filename:
                    img.save(f"{filename}.png")
                    print(f"QR 码已保存为 {filename}.png")
                else:
                    print("未保存")
            pause()
        elif choice == "2":
            if not BARCODE_AVAILABLE:
                print("python-barcode 库未安装")
                pause()
                continue
            print("支持的条形码类型:")
            print("UPC-A, UPC-E, EAN-13, EAN-8, JAN, ISBN, ISSN, Code39, Code93, Code128, Code11, Codabar, Plessey, MSI, I25, ITF, ITF14, St5, Msi")
            btype = safe_input("输入条形码类型: ").upper()
            data = safe_input("输入要编码的数据: ")
            if data and btype:
                try:
                    code = barcode.get(btype, data)
                    filename = safe_input("输入文件名 (不含扩展名): ")
                    if filename:
                        code.save(f"{filename}")
                        print(f"条形码已保存为 {filename}.svg")
                    else:
                        print("未保存")
                except Exception as e:
                    print(f"错误: {e}")
            pause()
        elif choice == "0":
            break
        else:
            print("无效选项")
            pause()

def generate_fake_mc_token():
    """生成假的Minecraft Access Token"""
    # 生成假JWT格式的token
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({
        "xuid": str(random.randint(100000000000000000, 999999999999999999)),
        "agg": "Adult",
        "sub": str(uuid.uuid4()),
        "auth": "XBOX",
        "ns": "default",
        "roles": [],
        "iss": "authentication",
        "flags": ["multiplayer", "orders_2022", "msamigration_stage4", "twofactorauth"],
        "profiles": {"mc": str(uuid.uuid4())},
        "platform": "PC_LAUNCHER",
        "pfd": [{"type": "mc", "id": str(uuid.uuid4()), "name": generate_random_minecraft_name()}],
        "nbf": int(time.time()),
        "exp": int(time.time()) + 86400,
        "iat": int(time.time()),
        "aid": "00000000-0000-0000-0000-00004c12ae6f"
    }).encode()).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(os.urandom(64)).decode().rstrip('=')
    return f"{header}.{payload}.{signature}"

def generate_fake_mc_card():
    """生成假的Minecraft卡密"""
    # 根據用戶提供的格式，生成類似的隨機字符串
    chars = string.ascii_letters + string.digits + '-_'
    return ''.join(random.choice(chars) for _ in range(100))  # 調整長度

def fake_mc_account_menu():
    """假我的世界賬號生成器"""
    title = translate_text("假我的世界賬號生成器")
    output_format = "account"  # "account" 或 "card"
    show_token = True
    quantity = 1
    
    while True:
        print_header(title)
        print(translate_text("当前设置:"))
        print(f"  1) {translate_text('输出格式')}: {'賬號' if output_format == 'account' else '卡密'}")
        print(f"  2) {translate_text('显示Token')}: {show_token}")
        print(f"  3) {translate_text('输出数量')}: {quantity}")
        print(f"  4) {translate_text('生成')}")
        choice = safe_input(translate_text("选择") + " (1/2/3/4/0): ").strip()
        
        if choice == "1":
            output_format = "card" if output_format == "account" else "account"
        elif choice == "2":
            show_token = not show_token
        elif choice == "3":
            try:
                qty = int(safe_input(translate_text("输入输出数量: ")))
                if qty > 0:
                    quantity = qty
                else:
                    print(translate_text("数量必须大于0"))
            except ValueError:
                print(translate_text("无效数量"))
        elif choice == "4":
            # 生成數據
            outputs = []
            for _ in range(quantity):
                account = generate_minecraft_account('4')  # 使用現有的函數
                token = generate_fake_mc_token() if show_token else ""
                
                if output_format == "account":
                    # 格式：[Microsoft_Hit][MC][unban][1]email:password |McName:name [Hypixel: level]Accesstoken:token|name|uuid
                    level = f"[Hypixel: {account['level']}]"
                    uuid_str = str(uuid.uuid4())
                    output = f"[Microsoft_Hit][MC][unban][1]{account['email']}:{account['password']} |McName:{account['name']} {level}"
                    if show_token:
                        output += f"Accesstoken:{token}"
                    output += f"|{account['name']}|{uuid_str}"
                else:
                    # 卡密格式
                    output = generate_fake_mc_card()
                
                outputs.append(output)
            
            print(translate_text("生成的數據:"))
            for i, out in enumerate(outputs, 1):
                print(f"{i}. {out}")
            
            # 可選：保存到文件
            save = safe_input(translate_text("保存到文件? (y/n): ")).strip().lower()
            if save == 'y':
                filename = safe_input(translate_text("文件名: ")).strip()
                if filename:
                    with open(filename, 'w') as f:
                        for out in outputs:
                            f.write(out + '\n')
                    print(translate_text("已保存"))
            pause()
        elif choice == "0":
            break
        else:
            print(translate_text("无效选项"))
            pause()





def google_translate(text, src='auto', dest='en'):
    url = f"https://translate.googleapis.com/translate_a/single?client=gtx&sl={src}&tl={dest}&dt=t&q={urllib.parse.quote(text)}"
    response = requests.get(url)
    result = response.json()
    translated = result[0][0][0]
    return translated

def google_translate_menu():
    title = translate_text("Google翻译")
    print_header(title)
    text = safe_input(translate_text("请输入要翻译的文本: "))
    src = safe_input(translate_text("请输入源语言代码 (auto为自动检测): "))
    if not src:
        src = 'auto'
    dest = safe_input(translate_text("请输入目标语言代码 (en为英语): "))
    if not dest:
        dest = 'en'
    
    try:
        translated = google_translate(text, src, dest)
        print(translate_text("翻译结果:"))
        print(translated)
    except Exception as e:
        print(translate_text("翻译失败:") + str(e))
    pause()

def perlin_noise_menu():
    """柏林噪聲生成器 (Perlin Noise Generator)"""
    title = translate_text("柏林噪聲生成器")
    
    if not NUMPY_AVAILABLE:
        print_header(title)
        print(translate_text("错误: numpy 库未安装"))
        print(translate_text("请运行: pip install numpy"))
        pause()
        return
    
    if not PIL_AVAILABLE:
        print_header(title)
        print(translate_text("错误: PIL/Pillow 库未安装"))
        print(translate_text("请运行: pip install Pillow"))
        pause()
        return
    
    while True:
        print_header(title)
        print("1) " + translate_text("生成 2D 柏林噪聲圖像"))
        print("0) " + translate_text("返回主菜单"))
        
        choice = safe_input(translate_text("选择序号") + ": ").strip()
        
        if choice == "1":
            print_header(title)
            
            # 輸入寬度
            width_str = safe_input(translate_text("輸入圖像寬度 (默認 256): "))
            width = int(width_str) if width_str else 256
            
            # 輸入高度
            height_str = safe_input(translate_text("輸入圖像高度 (默認 256): "))
            height = int(height_str) if height_str else 256
            
            # 輸入縮放因子
            scale_str = safe_input(translate_text("輸入噪聲縮放因子 (默認 100): "))
            scale = float(scale_str) if scale_str else 100.0
            
            # 輸入八度數
            octaves_str = safe_input(translate_text("輸入八度數 (默認 4): "))
            octaves = int(octaves_str) if octaves_str else 4
            
            # 輸入持久性
            persistence_str = safe_input(translate_text("輸入持久性 (默認 0.5): "))
            persistence = float(persistence_str) if persistence_str else 0.5
            
            # 輸入層次
            lacunarity_str = safe_input(translate_text("輸入層次 (默認 2.0): "))
            lacunarity = float(lacunarity_str) if lacunarity_str else 2.0
            
            # 輸入隨機種子
            seed_str = safe_input(translate_text("輸入隨機種子 (默認隨機): "))
            seed = int(seed_str) if seed_str else random.randint(0, 10000)
            
            # 輸入輸出文件名
            filename = safe_input(translate_text("輸入輸出文件名 (默認 perlin_noise.png): "))
            if not filename:
                filename = "perlin_noise.png"
            
            try:
                # 生成噪聲圖像
                generate_perlin_noise_image(width, height, scale, octaves, persistence, lacunarity, seed, filename)
                print(translate_text("噪聲圖像已生成並保存為") + f" {filename}")
            except Exception as e:
                print(translate_text("錯誤") + f": {e}")
            
            pause()
        elif choice == "0":
            return
        else:
            print(translate_text("无效选项"))
            pause()

def generate_perlin_noise_image(width, height, scale, octaves, persistence, lacunarity, seed, filename):
    """生成簡單噪聲圖像 (模擬柏林噪聲)"""
    import numpy as np
    from PIL import Image
    
    # 設置隨機種子
    np.random.seed(seed)
    
    # 生成隨機噪聲
    noise = np.random.rand(height, width)
    
    # 應用簡單的濾波來模擬噪聲
    for _ in range(octaves):
        noise = np.add(noise, np.random.rand(height, width) * persistence)
        persistence *= lacunarity
    
    # 正規化到 0-255
    noise = (noise - np.min(noise)) / (np.max(noise) - np.min(noise)) * 255
    noise = noise.astype(np.uint8)
    
    # 創建圖像
    img = Image.fromarray(noise, mode='L')
    
    # 保存圖像
    img.save(filename)

def id_generator_menu():
    """身份證生成器"""
    title = translate_text("身份證生成器")
    
    while True:
        print_header(title)
        print("1) " + translate_text("中國大陸身份證"))
        print("2) " + translate_text("美國社會安全號碼"))
        print("3) " + translate_text("中華民國身份證"))
        print("4) " + translate_text("日本身份證"))
        print("5) " + translate_text("批量生成"))
        print("0) " + translate_text("返回主菜单"))
        
        choice = safe_input(translate_text("选择序号") + ": ").strip()
        
        if choice in ["1", "2", "3", "4", "5"]:
            if choice == "5":
                # 批量生成
                sub_choice = safe_input(translate_text("选择国家 (1-4): ")).strip()
                if sub_choice not in ["1", "2", "3", "4"]:
                    print(translate_text("无效选项"))
                    pause()
                    continue
                country = {
                    "1": "中國大陸",
                    "2": "美國",
                    "3": "中華民國",
                    "4": "日本"
                }[sub_choice]
                count_str = safe_input(translate_text("输入生成数量: "))
                try:
                    count = int(count_str)
                    if count <= 0:
                        raise ValueError
                except:
                    print(translate_text("无效数量"))
                    pause()
                    continue
            else:
                country = {
                    "1": "中國大陸",
                    "2": "美國",
                    "3": "中華民國",
                    "4": "日本"
                }[choice]
                count = 1
            
            print_header(translate_text("生成结果"))
            
            for i in range(count):
                if count > 1:
                    print(f"\n--- {i+1} ---")
                
                # 生成名稱
                name = generate_random_name(country)
                print(translate_text("姓名") + f": {name}")
                
                # 生成身份證
                id_number = generate_id_number(country)
                print(translate_text("身份證號碼") + f": {id_number}")
                
                # 生成地址
                address = generate_random_address(country)
                print(translate_text("地址") + f": {address}")
            
            pause()
        elif choice == "0":
            return
        else:
            print(translate_text("无效选项"))
            pause()

def generate_random_name(country):
    """生成隨機名稱"""
    if country == "中國大陸":
        surnames = ["王", "李", "张", "刘", "陈", "杨", "赵", "黄", "周", "吴", "徐", "孙", "胡", "朱", "高", "林", "何", "郭", "马", "罗", "梁", "宋", "郑", "谢", "韩", "唐"]
        given_names = ["明", "华", "志", "伟", "强", "军", "建", "国", "文", "德", "丽", "芳", "娜", "静", "敏", "燕", "婷", "玉", "红", "霞", "桂", "玲", "梅", "琳", "慧", "娟"]
        surname = random.choice(surnames)
        given = "".join(random.choices(given_names, k=random.randint(1, 2)))
        return surname + given
    elif country == "美國":
        first_names = ["John", "Jane", "Michael", "Sarah", "David", "Emma", "James", "Olivia", "Robert", "Sophia", "William", "Isabella", "Joseph", "Mia", "Charles", "Amelia", "Thomas", "Harper", "Daniel", "Evelyn", "Matthew", "Abigail"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee"]
        return random.choice(first_names) + " " + random.choice(last_names)
    elif country == "中華民國":
        surnames = ["陳", "林", "黃", "張", "李", "王", "吳", "劉", "蔡", "楊", "許", "鄭", "謝", "洪", "曾", "周", "賴", "徐", "葉", "郭", "蘇", "潘", "莊", "呂", "江", "沈", "施"]
        given_names = ["志明", "美玲", "建國", "淑芬", "文華", "秀英", "家豪", "雅婷", "俊傑", "怡君", "宏偉", "佩君", "宗翰", "欣怡", "柏翰", "婉如", "冠宇", "詩涵", "宇軒", "芷涵", "子豪", "雅雯", "承翰", "怡萱"]
        return random.choice(surnames) + random.choice(given_names)
    elif country == "日本":
        surnames = ["佐藤", "鈴木", "高橋", "田中", "渡邊", "伊藤", "山本", "中村", "小林", "加藤", "吉田", "山田", "佐々木", "山口", "松本", "井上", "木村", "林", "斎藤", "清水", "山崎", "池田", "阿部", "森", "橋本", "石川"]
        given_names = ["太郎", "花子", "一郎", "美咲", "健太", "愛", "大輔", "桃子", "翔太", "奈々", "悠斗", "結衣", "直樹", "彩花", "拓也", "葵", "亮太", "美優", "大和", "紗季", "悠真", "莉子", "颯太", "陽菜", "蓮"]
        return random.choice(surnames) + " " + random.choice(given_names)
    return "Unknown"

def generate_id_number(country):
    """生成身份證號碼"""
    if country == "中國大陸":
        # 簡單模擬：地區碼(6位) + 生日(8位) + 順序碼(3位) + 校驗碼(1位)
        region = random.choice(["110101", "310101", "440101", "510101"])  # 北京、上海、廣州、成都
        birth_year = str(random.randint(1950, 2005))
        birth_month = str(random.randint(1, 12)).zfill(2)
        birth_day = str(random.randint(1, 28)).zfill(2)
        birth = birth_year + birth_month + birth_day
        sequence = str(random.randint(0, 999)).zfill(3)
        check_digit = str(random.randint(0, 9))
        return region + birth + sequence + check_digit
    elif country == "美國":
        # SSN: XXX-XX-XXXX
        return f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
    elif country == "中華民國":
        # 1字母 + 9數字
        letters = "ABCDEFGHJKLMNPQRSTUVXYWZIO"
        letter = random.choice(letters)
        numbers = "".join(str(random.randint(0, 9)) for _ in range(9))
        return letter + numbers
    elif country == "日本":
        # 簡單模擬：12位數字
        return "".join(str(random.randint(0, 9)) for _ in range(12))
    return "000000000000"

def generate_random_address(country):
    """生成隨機地址"""
    if country == "中國大陸":
        provinces = ["北京市", "上海市", "广东省", "江苏省", "山东省", "浙江省", "四川省", "湖北省", "湖南省", "福建省"]
        cities = ["北京市", "上海市", "广州市", "南京市", "济南市", "杭州市", "成都市", "武汉市", "长沙市", "福州市"]
        streets = ["人民路", "解放路", "中山路", "建设路", "和平路", "新华路", "胜利路", "光明路", "友谊路", "幸福路"]
        return f"{random.choice(provinces)}{random.choice(cities)}{random.choice(streets)}{random.randint(1, 999)}號"
    elif country == "美國":
        states = ["California", "Texas", "New York", "Florida", "Illinois", "Pennsylvania", "Ohio", "Georgia", "North Carolina", "Michigan"]
        cities = ["Los Angeles", "Houston", "New York", "Miami", "Chicago", "Philadelphia", "Columbus", "Atlanta", "Charlotte", "Detroit"]
        streets = ["Main St", "Oak Ave", "Elm St", "Pine Rd", "Maple Ln", "Cedar St", "Birch Rd", "Walnut St", "Chestnut Ave", "Spruce St"]
        return f"{random.randint(100, 9999)} {random.choice(streets)}, {random.choice(cities)}, {random.choice(states)}"
    elif country == "中華民國":
        counties = ["台北市", "新北市", "桃園市", "台中市", "高雄市", "台南市", "新竹市", "嘉義市"]
        districts = ["中正區", "中山區", "大安區", "文山區", "松山區", "信義區", "士林區", "內湖區"]
        roads = ["忠孝路", "中山路", "民生路", "和平路", "復興路", "光復路", "建國路", "信義路"]
        return f"{random.choice(counties)}{random.choice(districts)}{random.choice(roads)}{random.randint(1, 999)}號"
    elif country == "日本":
        prefectures = ["東京都", "大阪府", "神奈川県", "愛知県", "北海道", "福岡県", "京都府", "兵庫県", "千葉県", "埼玉県"]
        cities = ["東京", "大阪", "横浜", "名古屋", "札幌", "福岡", "京都", "神戸", "千葉", "さいたま"]
        wards = ["渋谷区", "新宿区", "中央区", "港区", "目黒区", "豊島区", "台東区", "墨田区", "江東区", "品川区"]
        return f"{random.choice(prefectures)}{random.choice(cities)}{random.choice(wards)}{random.randint(1, 999)}-{random.randint(1, 99)}"
    return "Unknown Address"

def check_version():
    """检查版本并自动更新"""
    if not REQUESTS_AVAILABLE:
        print(translate_text("requests 库不可用，无法检查版本"))
        return
    
    try:
        # 获取远程版本信息
        response = requests.get("https://raw.githubusercontent.com/SaonvWart/Tool/main/version.json")
        if response.status_code != 200:
            print(translate_text("无法获取版本信息"))
            return
        
        remote_data = response.json()
        remote_version = remote_data.get("version")
        
        if remote_version != Version:
            print(translate_text("发现新版本: ") + remote_version)
            update_choice = safe_input(translate_text("是否自动更新? (y/n): ")).strip().lower()
            if update_choice == 'y':
                if Form == "python":
                    # 下载并替换 Python 脚本
                    script_response = requests.get("https://raw.githubusercontent.com/SaonvWart/Tool/main/Tool.py")
                    if script_response.status_code == 200:
                        with open(__file__, 'wb') as f:
                            f.write(script_response.content)
                        print(translate_text("更新完成，请重新运行程序"))
                        sys.exit(0)
                    else:
                        print(translate_text("下载更新失败"))
                elif Form == "exe":
                    # 获取最新的 release
                    release_response = requests.get("https://api.github.com/repos/SaonvWart/Tool/releases/latest")
                    if release_response.status_code == 200:
                        release_data = release_response.json()
                        assets = release_data.get("assets", [])
                        if assets:
                            download_url = assets[0]["browser_download_url"]  # 假设第一个 asset 是 exe
                            exe_response = requests.get(download_url)
                            if exe_response.status_code == 200:
                                exe_path = os.path.join(os.getcwd(), "Tool-Edited.exe")
                                with open(exe_path, 'wb') as f:
                                    f.write(exe_response.content)
                                print(translate_text("更新下载完成: ") + exe_path)
                                print(translate_text("请手动替换原文件"))
                            else:
                                print(translate_text("下载 exe 失败"))
                        else:
                            print(translate_text("未找到 release assets"))
                    else:
                        print(translate_text("获取 release 信息失败"))
            else:
                print(translate_text("跳过更新"))
        else:
            print(translate_text("当前已是最新版本"))
    except Exception as e:
        print(translate_text("版本检查失败: ") + str(e))

def main_menu():
    """主菜单"""
    check_version()
    while True:
        title = translate_text("多功能生成工具箱")
        print_header(title)
        print("1) " + translate_text("卡密生成器"))
        print("2) " + translate_text("编码解码"))
        print("3) " + translate_text("字节计算"))
        print("4) " + translate_text("哈希计算"))
        print("5) " + translate_text("Base64 编码/解码"))
        print("6) " + translate_text("图片转 Base64"))
        print("7) " + translate_text("格式转换"))
        print("8) " + translate_text("RSA 加密/解密"))
        print("9) " + translate_text("AES 加密/解密"))
        print("10) " + translate_text("CSR 证书生成"))
        print("11) " + translate_text("UUID 生成器"))
        print("12) " + translate_text("HWID 生成器"))
        print("13) " + translate_text("漫画图片生成"))
        print("14) " + translate_text("国密 SM2 工具"))
        print("15) " + translate_text("二维码生成工具"))
        print("16) " + translate_text("假我的世界賬號生成"))
        print("17) " + translate_text("Google翻译"))
        print("18) " + translate_text("網盤API"))
        print("19) " + translate_text("柏林噪聲生成器"))
        print("20) " + translate_text("身份證生成器"))
        print("0) " + translate_text("退出"))
        choice = safe_input(translate_text("选择序号") + ": ").strip()
        if choice == "1":
            card_menu()
        elif choice == "2":
            encdec_menu()
        elif choice == "3":
            bytes_calc_menu()
        elif choice == "4":
            hash_menu()
        elif choice == "5":
            base64_menu()
        elif choice == "6":
            img2b64_menu()
        elif choice == "7":
            format_menu()
        elif choice == "8":
            rsa_menu()
        elif choice == "9":
            aes_menu()
        elif choice == "10":
            csr_menu()
        elif choice == "11":
            uuid_generator_menu()
        elif choice == "12":
            hwid_generator_menu()
        elif choice == "13":
            manga_image_generator_menu()
        elif choice == "14":
            sm2_menu()
        elif choice == "15":
            barcode_menu()
        elif choice == "16":
            fake_mc_account_menu()
        elif choice == "17":
            google_translate_menu()
        elif choice == "18":
            netdisk_api_menu()
        elif choice == "19":
            perlin_noise_menu()
        elif choice == "20":
            id_generator_menu()
        elif choice == "0":
            break
        else:
            print(translate_text("无效选项"))
            pause()
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n退出。")
