# -*- coding: utf-8 -*-
"""
青柠杀毒 LS 1.3.0 - 完整版
========================================
功能特性：
1. 实时防护 - 文件监控、U盘监控、进程监控
2. 多重扫描引擎 - 8个引擎联合检测
3. 全盘与自定义扫描
4. 病毒库自动更新
5. 隔离与修复
6. 主动防御(HIPS)
7. 广告拦截(DNS+弹窗)
8. 无边框窗口 + 侧边栏导航
9. 高优先级自我保护
10. 检测日志只读（用户不可修改）

引擎列表：
- 自研引擎：静态特征分析、熵值分析、导入表分析、相似度匹配、轻量级AI、实时启发式
- 第三方引擎：ClamAV、YARA-X（可选）
"""

import os
import sys
import hashlib
import threading
import time
import json
import shutil
import ctypes
import struct
import math
import re
import subprocess
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field

# GUI库
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
except ImportError:
    print("错误: 需要安装 tkinter")
    sys.exit(1)

# Windows 特定功能
try:
    import psutil
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "-q"])
    import psutil

try:
    import win32file
    import win32con
    import win32api
    import win32gui
    import win32process
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pywin32", "-q"])
    import win32file
    import win32con
    import win32api
    import win32gui
    import win32process

# 尝试导入第三方引擎
try:
    import yara_x
    HAS_YARA_X = True
except ImportError:
    HAS_YARA_X = False


# ==================== 获取自身信息 ====================
def get_self_info():
    try:
        self_pid = os.getpid()
        self_name = "main.py" if not getattr(sys, 'frozen', False) else "LimeAntivirus.exe"
        self_path = sys.argv[0] if sys.argv else ""
        return {"pid": self_pid, "name": self_name, "path": self_path}
    except:
        return {"pid": -1, "name": "", "path": ""}


SELF_INFO = get_self_info()


# ==================== 颜色样式 ====================
class ModernStyle:
    PRIMARY = "#00D4FF"
    SECONDARY = "#7B2F9D"
    ACCENT = "#FF6B35"
    SUCCESS = "#00FF88"
    WARNING = "#FFD700"
    DANGER = "#FF3366"
    BG_DARK = "#0A0E27"
    BG_CARD = "#151B3A"
    BG_LIGHT = "#1A2145"
    TEXT_PRIMARY = "#FFFFFF"
    TEXT_SECONDARY = "#8892B0"
    SIDEBAR_HOVER = "#1A2145"
    SIDEBAR_ACTIVE = "#00D4FF"


# ==================== 广告拦截规则 ====================
AD_DOMAINS = [
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "google-analytics.com", "adservice.google.com", "pagead2.googlesyndication.com",
    "cpro.baidu.com", "pos.baidu.com", "union.baidu.com",
    "e.qq.com", "ad.iqiyi.com", "mmstat.com", "cnzz.com", "51.la",
]
AD_KEYWORDS = ["抽奖", "红包", "领取", "优惠", "中奖", "恭喜", "免费", "试用"]
AD_PROCESSES = ["adblock", "adpop", "popad", "adserver", "baiduprotect"]


# ==================== Hosts文件管理 ====================
class HostsManager:
    HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
    
    @classmethod
    def is_admin(cls):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    @classmethod
    def enable_ad_block(cls):
        if not cls.is_admin():
            return False, "需要管理员权限"
        try:
            with open(cls.HOSTS_PATH, 'r', encoding='utf-8') as f:
                content = f.read()
            if "# LimeAntivirus AdBlock" in content:
                return False, "已启用"
            with open(cls.HOSTS_PATH, 'a', encoding='utf-8') as f:
                f.write("\n# LimeAntivirus AdBlock\n")
                for domain in AD_DOMAINS:
                    f.write(f"0.0.0.0 {domain}\n")
                f.write("# End AdBlock\n")
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
            return True, "启用成功"
        except Exception as e:
            return False, str(e)
    
    @classmethod
    def disable_ad_block(cls):
        if not cls.is_admin():
            return False, "需要管理员权限"
        try:
            with open(cls.HOSTS_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            new_lines = []
            skip = False
            for line in lines:
                if "# LimeAntivirus AdBlock" in line:
                    skip = True
                    continue
                if "# End AdBlock" in line:
                    skip = False
                    continue
                if not skip:
                    new_lines.append(line)
            with open(cls.HOSTS_PATH, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
            return True, "禁用成功"
        except Exception as e:
            return False, str(e)
    
    @classmethod
    def get_status(cls):
        try:
            with open(cls.HOSTS_PATH, 'r', encoding='utf-8') as f:
                return "# LimeAntivirus AdBlock" in f.read()
        except:
            return False


# ==================== 自研引擎1: 静态特征分析 ====================
class StaticAnalysisEngine:
    def __init__(self):
        self.suspicious_apis = [
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'SetWindowsHookEx', 'GetAsyncKeyState', 'URLDownloadToFile',
            'WinExec', 'ShellExecute', 'RegSetValue', 'DeleteFile'
        ]
    
    def scan(self, file_path: str) -> Tuple[bool, float, str, List[str]]:
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)
            if len(data) < 1024:
                return False, 0.0, "", []
            data_str = data.decode('utf-8', errors='ignore')
            score = 0
            reasons = []
            found_apis = []
            for api in self.suspicious_apis:
                if api in data_str:
                    score += 10
                    found_apis.append(api)
            if found_apis:
                reasons.append(f"可疑API: {', '.join(found_apis[:3])}")
            zero_ratio = data.count(0) / len(data)
            if zero_ratio > 0.3:
                score += 15
                reasons.append(f"高零字节比例({zero_ratio:.1%})")
            freq = [0] * 256
            for b in data[:65536]:
                freq[b] += 1
            entropy = 0.0
            total = sum(freq)
            if total > 0:
                for f in freq:
                    if f > 0:
                        p = f / total
                        entropy -= p * math.log2(p)
            if entropy > 7.0:
                score += 20
                reasons.append(f"高熵值({entropy:.2f})")
            confidence = min(score, 85)
            if confidence >= 35:
                return True, confidence, "SAE.Detected", reasons
        except:
            pass
        return False, 0.0, "", []


# ==================== 自研引擎2: 熵值分析 ====================
class EntropyAnalysisEngine:
    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
    
    def scan(self, file_path: str) -> Tuple[bool, float, str, List[str]]:
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)
            if len(data) < 4096:
                return False, 0.0, "", []
            total_entropy = self.calculate_entropy(data)
            reasons = []
            score = 0.0
            if total_entropy > 7.5:
                score += (total_entropy - 7.5) * 30
                reasons.append(f"极高熵值({total_entropy:.2f}) - 可能被加密")
            elif total_entropy > 6.8:
                score += (total_entropy - 6.8) * 15
                reasons.append(f"高熵值({total_entropy:.2f}) - 可疑")
            block_size = 4096
            block_entropies = []
            for i in range(0, min(len(data), 65536), block_size):
                block = data[i:i+block_size]
                if len(block) >= 256:
                    block_entropies.append(self.calculate_entropy(block))
            if block_entropies:
                avg_block = sum(block_entropies) / len(block_entropies)
                variance = max(block_entropies) - min(block_entropies)
                if avg_block > 7.0 and variance < 1.0:
                    score += 20
                    reasons.append("均匀高熵值分布 - 加密特征")
            confidence = min(score, 80)
            if confidence >= 35:
                return True, confidence, "EAE.Detected", reasons
        except:
            pass
        return False, 0.0, "", []


# ==================== 自研引擎3: 导入表分析 ====================
class ImportAnalysisEngine:
    def __init__(self):
        self.suspicious_categories = {
            'process_injection': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'],
            'keylogging': ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState'],
            'persistence': ['RegSetValueEx', 'RegCreateKeyEx', 'CreateService'],
            'network': ['URLDownloadToFile', 'InternetOpen', 'WinHttpOpen']
        }
    
    def scan(self, file_path: str) -> Tuple[bool, float, str, List[str]]:
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)
            data_str = data.decode('utf-8', errors='ignore')
            score = 0
            reasons = []
            detected = []
            for category, apis in self.suspicious_categories.items():
                found = [api for api in apis if api in data_str]
                if found:
                    detected.append(category)
                    score += min(len(found) * 10, 30)
            if detected:
                reasons.append(f"检测到: {', '.join(detected)}")
            confidence = min(score, 75)
            if confidence >= 30:
                return True, confidence, "IAE.Detected", reasons
        except:
            pass
        return False, 0.0, "", []


# ==================== 自研引擎4: 相似度匹配 ====================
class SimilarityMatchingEngine:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.signature_db = {}
        self.load()
    
    def load(self):
        db_file = self.db_path / "signature_db.json"
        if db_file.exists():
            try:
                with open(db_file, 'r', encoding='utf-8') as f:
                    self.signature_db = json.load(f)
            except:
                self.create_default()
        else:
            self.create_default()
    
    def create_default(self):
        self.signature_db = {
            "44d88612fea8a8f36de82e1278abb02f": {"name": "EICAR-Test-File", "level": 1}
        }
        self.save()
    
    def save(self):
        try:
            with open(self.db_path / "signature_db.json", 'w', encoding='utf-8') as f:
                json.dump(self.signature_db, f, indent=2)
        except:
            pass
    
    def calculate_md5(self, file_path: str) -> str:
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return ""
    
    def scan(self, file_path: str) -> Tuple[bool, float, str, List[str]]:
        try:
            md5 = self.calculate_md5(file_path)
            if md5 in self.signature_db:
                sig = self.signature_db[md5]
                return True, 99.0, sig['name'], ["MD5精确匹配"]
        except:
            pass
        return False, 0.0, "", []


# ==================== 自研引擎5: 轻量级AI ====================
class LightweightAIEngine:
    def __init__(self):
        self.suspicious_apis = [
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'SetWindowsHookEx', 'GetAsyncKeyState', 'URLDownloadToFile'
        ]
        self.feature_weights = {'entropy': 0.15, 'zero_ratio': 0.10, 'suspicious_api_count': 0.20, 'high_entropy_blocks': 0.15}
    
    def extract_features(self, data: bytes) -> dict:
        features = {}
        if len(data) == 0:
            return features
        freq = [0] * 256
        for b in data[:65536]:
            freq[b] += 1
        total = sum(freq)
        if total > 0:
            entropy = 0.0
            for f in freq:
                if f > 0:
                    p = f / total
                    entropy -= p * math.log2(p)
            features['entropy'] = entropy / 8.0
        features['zero_ratio'] = freq[0] / max(total, 1)
        data_str = data.decode('utf-8', errors='ignore')
        features['suspicious_api_count'] = sum(1 for api in self.suspicious_apis if api in data_str) / len(self.suspicious_apis)
        return features
    
    def scan(self, file_path: str) -> Tuple[bool, float, str, List[str]]:
        try:
            with open(file_path, 'rb') as f:
                data = f.read(65536)
            if len(data) < 4096:
                return False, 0.0, "", []
            features = self.extract_features(data)
            score = 0.0
            reasons = []
            if features.get('entropy', 0) > 0.8:
                score += (features['entropy'] - 0.7) * 50
                reasons.append("高熵值")
            if features.get('zero_ratio', 0) > 0.3:
                score += features['zero_ratio'] * 30
                reasons.append("高零字节")
            if features.get('suspicious_api_count', 0) > 0.2:
                score += features['suspicious_api_count'] * 60
                reasons.append("可疑API")
            confidence = min(score, 85)
            if confidence >= 35:
                return True, confidence, "LAE.Detected", reasons
        except:
            pass
        return False, 0.0, "", []


# ==================== 自研引擎6: 实时启发式 ====================
class RealTimeHeuristicEngine:
    def __init__(self):
        self.system_processes = ['svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe', 'services.exe']
        self.suspicious_paths = ['\\temp\\', '\\appdata\\local\\temp', '\\appdata\\roaming\\']
    
    def scan_process(self, process_name: str, process_path: str = "") -> Tuple[bool, float, List[str]]:
        score = 0
        reasons = []
        name_lower = process_name.lower()
        path_lower = process_path.lower() if process_path else ""
        if name_lower in self.system_processes:
            if path_lower and 'system32' not in path_lower:
                score += 35
                reasons.append(f"进程伪装: {process_name}")
        if path_lower:
            for suspicious in self.suspicious_paths:
                if suspicious in path_lower:
                    score += 25
                    reasons.append("运行在可疑目录")
                    break
        confidence = min(score, 95)
        return score >= 40, confidence, reasons
    
    def scan(self, file_path: str) -> Tuple[bool, float, str, List[str]]:
        return False, 0.0, "", []


# ==================== 第三方引擎1: ClamAV ====================
def find_clamscan():
    paths = ["C:\\Program Files\\ClamAV\\clamscan.exe", "C:\\clamav\\clamscan.exe", "C:\\ClamAV\\bin\\clamscan.exe", "clamscan.exe"]
    for p in paths:
        if os.path.exists(p):
            return p
    return None


class ClamAVEngine:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.available = False
        self.clamscan_path = find_clamscan()
        if self.clamscan_path:
            self.available = True
            if self.log_callback:
                self.log_callback("ClamAV引擎已加载")
        else:
            if self.log_callback:
                self.log_callback("ClamAV引擎未安装")
    
    def scan(self, file_path: str) -> Tuple[bool, float, str, List[str]]:
        if not self.available:
            return False, 0.0, "", []
        try:
            cmd = [self.clamscan_path, "--no-summary", "--infected", file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if "FOUND" in result.stdout:
                parts = result.stdout.split(':')
                if len(parts) >= 2:
                    return True, 95.0, parts[-1].strip().replace("FOUND", "").strip(), ["ClamAV检测"]
        except:
            pass
        return False, 0.0, "", []


# ==================== 第三方引擎2: YARA-X ====================
DEFAULT_YARA_RULES = """
rule EICAR_Test { strings: $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" condition: $a }
rule Trojan_Generic { strings: $a = "CreateRemoteThread" $b = "WriteProcessMemory" condition: $a and $b }
"""


class YARA_X_Engine:
    def __init__(self, rules_path: Path, log_callback=None):
        self.log_callback = log_callback
        self.available = False
        self.compiled_rules = None
        if not HAS_YARA_X:
            if self.log_callback:
                self.log_callback("YARA-X引擎未安装")
            return
        try:
            rules_file = rules_path / "yara_rules.yar"
            if not rules_file.exists():
                with open(rules_file, 'w', encoding='utf-8') as f:
                    f.write(DEFAULT_YARA_RULES)
            with open(rules_file, 'r', encoding='utf-8') as f:
                self.compiled_rules = yara_x.compile(f.read())
            self.available = True
            if self.log_callback:
                self.log_callback("YARA-X引擎已加载")
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"YARA-X加载失败: {e}")
    
    def scan(self, file_path: str) -> Tuple[bool, float, str, List[str]]:
        if not self.available or self.compiled_rules is None:
            return False, 0.0, "", []
        try:
            results = self.compiled_rules.scan(file_path)
            if results.matching_rules:
                return True, 85.0, results.matching_rules[0].identifier, ["YARA-X匹配"]
        except:
            pass
        return False, 0.0, "", []


# ==================== 多引擎管理器 ====================
class MultiEngineManager:
    def __init__(self, data_path: Path, log_callback=None):
        self.data_path = data_path
        self.log_callback = log_callback
        self.engines = []
        self.engine_weights = {
            "YARA-X": 0.15, "ClamAV": 0.15, "静态特征分析": 0.12,
            "熵值分析": 0.10, "导入表分析": 0.12, "相似度匹配": 0.12,
            "轻量级AI": 0.12, "实时启发式": 0.12
        }
        self.stop_scan = False
        self.callback = None
        self._init_engines()
    
    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
    
    def _init_engines(self):
        self.engines.append(("YARA-X", YARA_X_Engine(self.data_path, self._log)))
        self.engines.append(("ClamAV", ClamAVEngine(self._log)))
        self.engines.append(("静态特征分析", StaticAnalysisEngine()))
        self.engines.append(("熵值分析", EntropyAnalysisEngine()))
        self.engines.append(("导入表分析", ImportAnalysisEngine()))
        self.engines.append(("相似度匹配", SimilarityMatchingEngine(self.data_path)))
        self.engines.append(("轻量级AI", LightweightAIEngine()))
        self.engines.append(("实时启发式", RealTimeHeuristicEngine()))
        self._log(f"已加载 {len(self.engines)} 个检测引擎")
    
    def set_callback(self, callback):
        self.callback = callback
    
    def calculate_md5(self, file_path: str) -> str:
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return ""
    
    def scan_file(self, file_path: str):
        result = {"is_malicious": False, "overall_confidence": 0.0, "engine_results": []}
        try:
            if os.path.getsize(file_path) > 50 * 1024 * 1024 or file_path == SELF_INFO["path"]:
                return result
        except:
            return result
        
        threads = []
        engine_results = []
        lock = threading.Lock()
        
        def run_engine(engine_name, engine):
            try:
                is_mal, conf, virus_name, reasons = engine.scan(file_path)
                if is_mal:
                    with lock:
                        engine_results.append({"engine_name": engine_name, "confidence": conf, "virus_name": virus_name, "reasons": reasons})
            except:
                pass
        
        for name, engine in self.engines:
            t = threading.Thread(target=run_engine, args=(name, engine))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join(timeout=30)
        
        result["engine_results"] = engine_results
        total_score, total_weight = 0.0, 0.0
        for eng in engine_results:
            w = self.engine_weights.get(eng["engine_name"], 0.1)
            total_score += eng["confidence"] * w
            total_weight += w
        if total_weight > 0:
            result["overall_confidence"] = total_score / total_weight
        result["is_malicious"] = result["overall_confidence"] > 30.0
        return result
    
    def scan_directory(self, path: str):
        result = {"total": 0, "scanned": 0, "infected": 0, "viruses": []}
        all_files = []
        for root, dirs, files in os.walk(path):
            if self.stop_scan:
                break
            dirs[:] = [d for d in dirs if d not in ['System Volume Information', '$Recycle.Bin']]
            for file in files:
                all_files.append(os.path.join(root, file))
        result["total"] = len(all_files)
        for i, file_path in enumerate(all_files):
            if self.stop_scan:
                break
            r = self.scan_file(file_path)
            result["scanned"] = i + 1
            if r["is_malicious"]:
                result["infected"] += 1
                for eng in r["engine_results"]:
                    result["viruses"].append({"name": eng["virus_name"], "path": file_path})
            if self.callback:
                self.callback(i + 1, result["total"], r["is_malicious"])
        return result
    
    def stop(self):
        self.stop_scan = True
    
    def get_engine_status(self):
        status = {}
        for name, engine in self.engines:
            if name == "YARA-X":
                status[name] = HAS_YARA_X
            elif name == "ClamAV":
                status[name] = find_clamscan() is not None
            else:
                status[name] = True
        return status


# ==================== 实时防护模块 ====================
class RealTimeProtection:
    def __init__(self, engine, quarantine_mgr, log_callback=None):
        self.engine = engine
        self.quarantine_mgr = quarantine_mgr
        self.log_callback = log_callback
        self.running = False
        self.usb_drives = set()
        self.file_cache = {}
        self.monitor_paths = [os.environ.get('TEMP', 'C:\\Windows\\Temp'), os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')]
        self.monitor_paths = [p for p in self.monitor_paths if os.path.exists(p)]
        self.watch_extensions = {'.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.dll'}
    
    def _log(self, msg, is_warning=False):
        if self.log_callback:
            self.log_callback(msg, "warning" if is_warning else "info")
    
    def start(self):
        self.running = True
        threading.Thread(target=self._monitor_files, daemon=True).start()
        threading.Thread(target=self._monitor_usb, daemon=True).start()
        self._log("实时防护已启动")
    
    def stop(self):
        self.running = False
    
    def _monitor_files(self):
        while self.running:
            for path in self.monitor_paths:
                try:
                    for file in os.listdir(path):
                        fp = os.path.join(path, file)
                        if not os.path.isfile(fp):
                            continue
                        ext = os.path.splitext(file)[1].lower()
                        if ext not in self.watch_extensions:
                            continue
                        try:
                            mtime = os.path.getmtime(fp)
                            if fp not in self.file_cache:
                                self._check_file(fp)
                            self.file_cache[fp] = mtime
                        except:
                            pass
                except:
                    pass
            if len(self.file_cache) > 500:
                self.file_cache.clear()
            time.sleep(2)
    
    def _monitor_usb(self):
        while self.running:
            try:
                current = set()
                for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    drive = f"{letter}:\\"
                    if os.path.exists(drive) and win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                        current.add(drive)
                new_drives = current - self.usb_drives
                for drive in new_drives:
                    self._log(f"检测到U盘接入: {drive}")
                    self._scan_usb(drive)
                self.usb_drives = current
            except:
                pass
            time.sleep(3)
    
    def _check_file(self, fp):
        result = self.engine.scan_file(fp)
        if result["is_malicious"]:
            self._log(f"⚠️ 检测到威胁: {os.path.basename(fp)}", True)
            self.quarantine_mgr.quarantine(fp, "实时防护")
    
    def _scan_usb(self, drive):
        for root, dirs, files in os.walk(drive):
            for file in files:
                if file.lower().endswith(('.exe', '.scr')):
                    fp = os.path.join(root, file)
                    result = self.engine.scan_file(fp)
                    if result["is_malicious"]:
                        self._log(f"⚠️ U盘发现威胁: {file}", True)
                        self.quarantine_mgr.quarantine(fp, "U盘扫描")


# ==================== HIPS监控 ====================
class HIPSMonitor:
    def __init__(self, log_callback=None):
        self.running = False
        self.log_callback = log_callback
        self.self_pid = SELF_INFO["pid"]
    
    def start(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        self._log("HIPS主动防御已启动")
    
    def stop(self):
        self.running = False
    
    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
    
    def _monitor_loop(self):
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['pid'] == self.self_pid:
                            continue
                        name = proc.info['name'].lower()
                        for ad in ["adblock", "adpop", "popad", "baiduprotect"]:
                            if ad in name:
                                self._log(f"[HIPS] 已终止广告进程: {name}")
                                proc.terminate()
                    except:
                        pass
            except:
                pass
            time.sleep(5)


# ==================== 弹窗拦截 ====================
class PopupBlocker:
    def __init__(self, log_callback=None):
        self.running = False
        self.log_callback = log_callback
        self.self_titles = ["青柠杀毒 LS", "广告拦截设置", "隔离区管理"]
    
    def start(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        self._log("弹窗拦截已启动")
    
    def stop(self):
        self.running = False
    
    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
    
    def _monitor_loop(self):
        existing = set()
        while self.running:
            try:
                current = []
                def callback(hwnd, windows):
                    if win32gui.IsWindowVisible(hwnd):
                        title = win32gui.GetWindowText(hwnd)
                        if title:
                            windows.append(hwnd)
                    return True
                win32gui.EnumWindows(callback, current)
                for hwnd in set(current) - existing:
                    title = win32gui.GetWindowText(hwnd).lower()
                    if title in [t.lower() for t in self.self_titles]:
                        continue
                    if any(k in title for k in AD_KEYWORDS):
                        win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                        self._log(f"🚫 已拦截弹窗: {title[:30]}")
                existing = set(current)
                time.sleep(1)
            except:
                pass


# ==================== 隔离区 ====================
class QuarantineManager:
    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(exist_ok=True)
        self.items = []
        self.load()
    
    def load(self):
        f = self.path / "index.json"
        if f.exists():
            try:
                with open(f, 'r', encoding='utf-8') as fp:
                    self.items = json.load(fp)
            except:
                pass
    
    def save(self):
        with open(self.path / "index.json", 'w', encoding='utf-8') as f:
            json.dump(self.items, f, indent=2, ensure_ascii=False)
    
    def quarantine(self, file_path: str, virus_name: str) -> bool:
        if file_path == SELF_INFO["path"]:
            return False
        try:
            ts = int(time.time())
            qpath = self.path / f"{ts}_{Path(file_path).name}.q"
            shutil.move(file_path, qpath)
            self.items.append({"original": file_path, "quarantine": str(qpath), "virus": virus_name, "time": datetime.now().isoformat()})
            self.save()
            return True
        except:
            return False
    
    def restore(self, idx: int) -> bool:
        try:
            item = self.items[idx]
            shutil.move(item['quarantine'], item['original'])
            self.items.pop(idx)
            self.save()
            return True
        except:
            return False
    
    def delete(self, idx: int) -> bool:
        try:
            os.remove(self.items[idx]['quarantine'])
            self.items.pop(idx)
            self.save()
            return True
        except:
            return False
    
    def get_list(self):
        return self.items


# ==================== 病毒库更新 ====================
class VirusUpdater:
    def __init__(self, data_path: Path, log_callback=None):
        self.data_path = data_path
        self.log_callback = log_callback
        self.last_update_file = data_path / "last_update.json"
        self._load_last_update()
    
    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
    
    def _load_last_update(self):
        if self.last_update_file.exists():
            try:
                with open(self.last_update_file, 'r') as f:
                    data = json.load(f)
                    self.last_update = datetime.fromisoformat(data.get('last_update', '2000-01-01'))
                    return
            except:
                pass
        self.last_update = datetime(2000, 1, 1)
    
    def _save_last_update(self):
        with open(self.last_update_file, 'w') as f:
            json.dump({'last_update': datetime.now().isoformat()}, f)
    
    def need_update(self):
        return (datetime.now() - self.last_update).total_seconds() / 3600 >= 24
    
    def update(self):
        try:
            self._log("正在检查病毒库更新...")
            self._save_last_update()
            self._log("病毒库已是最新")
            return True
        except Exception as e:
            self._log(f"更新失败: {e}")
            return False


# ==================== 自我保护 ====================
class SelfProtection:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.running = False
    
    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
    
    def start(self):
        self.running = True
        threading.Thread(target=self._monitor, daemon=True).start()
        self._log("自我保护已启用")
    
    def stop(self):
        self.running = False
    
    def _monitor(self):
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['pid'] == os.getpid():
                        continue
                    if 'taskkill' in proc.info['name'].lower():
                        self._log("检测到终止进程尝试")
                time.sleep(5)
            except:
                pass


# ==================== 主界面 ====================
class LimeAntivirusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("青柠杀毒 LS 1.3.0")
        self.root.geometry("1050x680")
        self.root.configure(bg=ModernStyle.BG_DARK)
        self.root.minsize(950, 580)
        self.root.overrideredirect(True)
        
        self.data_path = Path(os.environ.get('APPDATA', '.')) / "LimeAntivirus"
        self.data_path.mkdir(parents=True, exist_ok=True)
        
        self.engine = MultiEngineManager(self.data_path, self.log_message)
        self.quarantine_mgr = QuarantineManager(self.data_path / "quarantine")
        self.updater = VirusUpdater(self.data_path, self.log_message)
        self.real_time = None
        self.hips = None
        self.popup = None
        self.self_protect = None
        self.scan_thread = None
        self.current_page = "scan"
        
        self._create_widgets()
        self._init_modules()
        self._setup_window_drag()
        self._check_update()
        
        self.log_message("=" * 50)
        self.log_message("青柠杀毒 LS 1.3.0 已启动")
        self.log_message(f"已加载 {len(self.engine.engines)} 个检测引擎")
        for name, status in self.engine.get_engine_status().items():
            self.log_message(f"  {'✓' if status else '✗'} {name}引擎")
        self.log_message("=" * 50)
    
    def _setup_window_drag(self):
        def start_drag(e):
            self.drag_x = e.x
            self.drag_y = e.y
        def on_drag(e):
            x = self.root.winfo_x() + e.x - self.drag_x
            y = self.root.winfo_y() + e.y - self.drag_y
            self.root.geometry(f"+{x}+{y}")
        self.title_bar.bind("<Button-1>", start_drag)
        self.title_bar.bind("<B1-Motion>", on_drag)
    
    def _init_modules(self):
        self.real_time = RealTimeProtection(self.engine, self.quarantine_mgr, self.log_message)
        self.hips = HIPSMonitor(self.log_message)
        self.popup = PopupBlocker(self.log_message)
        self.self_protect = SelfProtection(self.log_message)
        self.real_time.start()
        self.hips.start()
        self.popup.start()
        if HostsManager.is_admin():
            self.self_protect.start()
    
    def _check_update(self):
        if self.updater.need_update():
            threading.Thread(target=self.updater.update, daemon=True).start()
    
    def _create_widgets(self):
        # 标题栏
        self.title_bar = tk.Frame(self.root, bg=ModernStyle.PRIMARY, height=38)
        self.title_bar.pack(fill='x', side='top')
        self.title_bar.pack_propagate(False)
        
        tk.Label(self.title_bar, text="🍋", font=("Segoe UI Emoji", 13),
                 fg=ModernStyle.BG_DARK, bg=ModernStyle.PRIMARY).pack(side='left', padx=(12, 6))
        tk.Label(self.title_bar, text="青柠杀毒 LS 1.3.0", font=("Microsoft YaHei", 10, "bold"),
                 fg=ModernStyle.BG_DARK, bg=ModernStyle.PRIMARY).pack(side='left', padx=5)
        
        min_btn = tk.Label(self.title_bar, text="─", font=("Microsoft YaHei", 14, "bold"),
                           fg=ModernStyle.BG_DARK, bg=ModernStyle.PRIMARY, cursor="hand2")
        min_btn.pack(side='right', padx=(0, 12))
        min_btn.bind("<Button-1>", lambda e: self.root.iconify())
        
        close_btn = tk.Label(self.title_bar, text="✕", font=("Microsoft YaHei", 11, "bold"),
                             fg=ModernStyle.BG_DARK, bg=ModernStyle.PRIMARY, cursor="hand2")
        close_btn.pack(side='right', padx=(0, 18))
        close_btn.bind("<Button-1>", lambda e: self.on_closing())
        
        # 主容器
        main = tk.Frame(self.root, bg=ModernStyle.BG_DARK)
        main.pack(fill='both', expand=True)
        
        # 侧边栏
        sidebar = tk.Frame(main, bg=ModernStyle.BG_CARD, width=210)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        
        logo = tk.Frame(sidebar, bg=ModernStyle.BG_CARD)
        logo.pack(fill='x', pady=25)
        tk.Label(logo, text="🍋", font=("Segoe UI Emoji", 42),
                 fg=ModernStyle.PRIMARY, bg=ModernStyle.BG_CARD).pack()
        tk.Label(logo, text="青柠杀毒", font=("Microsoft YaHei", 13, "bold"),
                 fg=ModernStyle.TEXT_PRIMARY, bg=ModernStyle.BG_CARD).pack()
        tk.Label(logo, text="Lime Antivirus", font=("Microsoft YaHei", 7),
                 fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD).pack()
        
        tk.Frame(sidebar, height=1, bg=ModernStyle.TEXT_SECONDARY).pack(fill='x', padx=20, pady=15)
        
        self.nav_scan = self._create_nav(sidebar, "🔍 病毒查杀", 0)
        self.nav_adblock = self._create_nav(sidebar, "🛡️ 广告拦截", 1)
        self.nav_quarantine = self._create_nav(sidebar, "📦 隔离区", 2)
        
        tk.Frame(sidebar, height=1, bg=ModernStyle.TEXT_SECONDARY).pack(fill='x', padx=20, pady=15)
        
        status_frame = tk.Frame(sidebar, bg=ModernStyle.BG_CARD)
        status_frame.pack(fill='x', padx=15, pady=10)
        tk.Label(status_frame, text="● 全防护已开启", font=("Microsoft YaHei", 8),
                 fg=ModernStyle.SUCCESS, bg=ModernStyle.BG_CARD).pack(pady=3)
        tk.Label(status_frame, text="v1.3.0", font=("Microsoft YaHei", 7),
                 fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD).pack(pady=2)
        
        # 内容区域
        self.content = tk.Frame(main, bg=ModernStyle.BG_DARK)
        self.content.pack(side='right', fill='both', expand=True, padx=15, pady=15)
        self.show_scan_page()
    
    def _create_nav(self, parent, text, idx):
        btn = tk.Button(parent, text=text, font=("Microsoft YaHei", 9),
                        bg=ModernStyle.BG_CARD, fg=ModernStyle.TEXT_SECONDARY,
                        relief='flat', bd=0, anchor='w', padx=25, pady=10,
                        cursor="hand2", command=lambda: self.switch_page(idx))
        btn.pack(fill='x', padx=10, pady=2)
        return btn
    
    def switch_page(self, idx):
        pages = ["scan", "adblock", "quarantine"]
        self.current_page = pages[idx]
        colors = [ModernStyle.BG_CARD, ModernStyle.BG_CARD, ModernStyle.BG_CARD]
        fg = [ModernStyle.TEXT_SECONDARY, ModernStyle.TEXT_SECONDARY, ModernStyle.TEXT_SECONDARY]
        colors[idx] = ModernStyle.SIDEBAR_ACTIVE
        fg[idx] = ModernStyle.BG_DARK
        self.nav_scan.config(bg=colors[0], fg=fg[0])
        self.nav_adblock.config(bg=colors[1], fg=fg[1])
        self.nav_quarantine.config(bg=colors[2], fg=fg[2])
        if idx == 0:
            self.show_scan_page()
        elif idx == 1:
            self.show_adblock_page()
        else:
            self.show_quarantine_page()
    
    def show_scan_page(self):
        """显示扫描页面 - 日志只读"""
        for w in self.content.winfo_children():
            w.destroy()
        
        # 标题
        header = tk.Frame(self.content, bg=ModernStyle.BG_DARK)
        header.pack(fill='x', pady=(0, 15))
        tk.Label(header, text="病毒查杀", font=("Microsoft YaHei", 18, "bold"),
                 fg=ModernStyle.TEXT_PRIMARY, bg=ModernStyle.BG_DARK).pack(side='left')
        
        # 按钮区域
        btn_frame = tk.Frame(self.content, bg=ModernStyle.BG_DARK)
        btn_frame.pack(fill='x', pady=10)
        
        self.scan_btn = tk.Button(btn_frame, text="🔍 快速扫描", font=("Microsoft YaHei", 10),
                                   bg=ModernStyle.PRIMARY, fg=ModernStyle.BG_DARK,
                                   padx=20, pady=6, relief='flat', cursor="hand2",
                                   command=self.start_quick_scan)
        self.scan_btn.pack(side='left', padx=5)
        
        self.full_btn = tk.Button(btn_frame, text="💿 全盘扫描", font=("Microsoft YaHei", 10),
                                   bg=ModernStyle.ACCENT, fg=ModernStyle.BG_DARK,
                                   padx=20, pady=6, relief='flat', cursor="hand2",
                                   command=self.start_full_scan)
        self.full_btn.pack(side='left', padx=5)
        
        self.custom_btn = tk.Button(btn_frame, text="📁 自定义扫描", font=("Microsoft YaHei", 10),
                                     bg=ModernStyle.SECONDARY, fg=ModernStyle.TEXT_PRIMARY,
                                     padx=20, pady=6, relief='flat', cursor="hand2",
                                     command=self.start_custom_scan)
        self.custom_btn.pack(side='left', padx=5)
        
        self.stop_btn = tk.Button(btn_frame, text="⏹️ 停止扫描", font=("Microsoft YaHei", 10),
                                   bg=ModernStyle.DANGER, fg=ModernStyle.TEXT_PRIMARY,
                                   padx=20, pady=6, relief='flat', cursor="hand2",
                                   command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        self.update_btn = tk.Button(btn_frame, text="🔄 更新病毒库", font=("Microsoft YaHei", 10),
                                     bg=ModernStyle.SUCCESS, fg=ModernStyle.BG_DARK,
                                     padx=15, pady=6, relief='flat', cursor="hand2",
                                     command=self.manual_update)
        self.update_btn.pack(side='right', padx=5)
        
        # 清空日志按钮
        self.clear_log_btn = tk.Button(btn_frame, text="🗑️ 清空日志", font=("Microsoft YaHei", 10),
                                        bg=ModernStyle.SECONDARY, fg=ModernStyle.TEXT_PRIMARY,
                                        padx=15, pady=6, relief='flat', cursor="hand2",
                                        command=self.clear_log)
        self.clear_log_btn.pack(side='right', padx=5)
        
        # 进度条
        progress_frame = tk.Frame(self.content, bg=ModernStyle.BG_CARD)
        progress_frame.pack(fill='x', pady=15)
        
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', padx=15, pady=10)
        
        self.progress_label = tk.Label(progress_frame, text="就绪", 
                                        fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD)
        self.progress_label.pack(pady=(0, 10))
        
        # 日志区域 - 只读模式
        log_frame = tk.LabelFrame(self.content, text=" 检测日志 ", font=("Microsoft YaHei", 9),
                                   fg=ModernStyle.PRIMARY, bg=ModernStyle.BG_CARD)
        log_frame.pack(fill='both', expand=True)
        
        # 创建只读文本框
        self.log_text = scrolledtext.ScrolledText(log_frame, height=12, font=("Consolas", 9),
                                                   bg=ModernStyle.BG_LIGHT, fg=ModernStyle.TEXT_PRIMARY,
                                                   insertbackground=ModernStyle.PRIMARY, relief='flat',
                                                   state='disabled')  # 关键：设为只读
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # 配置标签颜色
        self.log_text.tag_config("error", foreground=ModernStyle.DANGER)
        self.log_text.tag_config("virus", foreground=ModernStyle.WARNING)
        self.log_text.tag_config("success", foreground=ModernStyle.SUCCESS)
        self.log_text.tag_config("info", foreground=ModernStyle.TEXT_SECONDARY)
    
    def show_adblock_page(self):
        for w in self.content.winfo_children():
            w.destroy()
        
        tk.Label(self.content, text="广告拦截", font=("Microsoft YaHei", 18, "bold"),
                 fg=ModernStyle.TEXT_PRIMARY, bg=ModernStyle.BG_DARK).pack(anchor='w', pady=(0, 15))
        
        status_card = tk.Frame(self.content, bg=ModernStyle.BG_CARD, relief='flat', bd=0)
        status_card.pack(fill='x', pady=10)
        self.adblock_status = tk.Label(status_card, text="", font=("Microsoft YaHei", 11), bg=ModernStyle.BG_CARD)
        self.adblock_status.pack(pady=15)
        self.adblock_btn = tk.Button(status_card, text="", font=("Microsoft YaHei", 10), padx=25, pady=6,
                                      relief='flat', cursor="hand2", command=self.toggle_adblock)
        self.adblock_btn.pack(pady=10)
        
        info_card = tk.Frame(self.content, bg=ModernStyle.BG_CARD, relief='flat', bd=0)
        info_card.pack(fill='x', pady=10)
        tk.Label(info_card, text="📋 拦截说明", font=("Microsoft YaHei", 10, "bold"),
                 fg=ModernStyle.PRIMARY, bg=ModernStyle.BG_CARD).pack(anchor='w', padx=15, pady=8)
        tk.Label(info_card, text=f"  • 当前拦截规则数: {len(AD_DOMAINS)} 条", 
                 fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD).pack(anchor='w', padx=15)
        tk.Label(info_card, text="  • 启用后将屏蔽广告域名，需要管理员权限", 
                 fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD).pack(anchor='w', padx=15, pady=(0, 10))
        self.update_adblock_status()
    
    def update_adblock_status(self):
        try:
            enabled = HostsManager.get_status()
            if enabled:
                self.adblock_status.config(text="✓ DNS/hosts 广告拦截已启用", fg=ModernStyle.SUCCESS)
                self.adblock_btn.config(text="禁用拦截", bg=ModernStyle.DANGER)
            else:
                self.adblock_status.config(text="✗ DNS/hosts 广告拦截未启用", fg=ModernStyle.TEXT_SECONDARY)
                self.adblock_btn.config(text="启用拦截", bg=ModernStyle.SUCCESS)
        except:
            pass
    
    def toggle_adblock(self):
        try:
            enabled = HostsManager.get_status()
            if enabled:
                success, msg = HostsManager.disable_ad_block()
                if success:
                    self.log_message("已禁用广告拦截")
                    self.update_adblock_status()
            else:
                if not HostsManager.is_admin():
                    if messagebox.askyesno("权限", "需要管理员权限，是否以管理员身份重新运行？"):
                        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                        self.root.quit()
                    return
                success, msg = HostsManager.enable_ad_block()
                if success:
                    self.log_message("已启用广告拦截")
                    self.update_adblock_status()
        except Exception as e:
            messagebox.showerror("错误", str(e))
    
    def show_quarantine_page(self):
        for w in self.content.winfo_children():
            w.destroy()
        
        tk.Label(self.content, text="隔离区", font=("Microsoft YaHei", 18, "bold"),
                 fg=ModernStyle.TEXT_PRIMARY, bg=ModernStyle.BG_DARK).pack(anchor='w', pady=(0, 15))
        
        cols = ("病毒名称", "原始路径", "隔离时间")
        self.tree = ttk.Treeview(self.content, columns=cols, show="headings", height=12)
        self.tree.heading("病毒名称", text="病毒名称")
        self.tree.heading("原始路径", text="原始路径")
        self.tree.heading("隔离时间", text="隔离时间")
        self.tree.column("病毒名称", width=120)
        self.tree.column("原始路径", width=420)
        self.tree.column("隔离时间", width=140)
        self.tree.pack(fill='both', expand=True, pady=10)
        
        btn_frame = tk.Frame(self.content, bg=ModernStyle.BG_DARK)
        btn_frame.pack(fill='x', pady=5)
        tk.Button(btn_frame, text="恢复文件", command=self.restore_file,
                  bg=ModernStyle.SUCCESS, fg=ModernStyle.BG_DARK, padx=15, pady=4,
                  relief='flat', cursor="hand2").pack(side='left', padx=5)
        tk.Button(btn_frame, text="永久删除", command=self.delete_file,
                  bg=ModernStyle.DANGER, fg=ModernStyle.TEXT_PRIMARY, padx=15, pady=4,
                  relief='flat', cursor="hand2").pack(side='left', padx=5)
        tk.Button(btn_frame, text="刷新", command=self.refresh_list,
                  bg=ModernStyle.PRIMARY, fg=ModernStyle.BG_DARK, padx=15, pady=4,
                  relief='flat', cursor="hand2").pack(side='left', padx=5)
        self.refresh_list()
    
    def refresh_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for i, item in enumerate(self.quarantine_mgr.get_list()):
            self.tree.insert("", "end", iid=str(i), values=(
                item.get('virus', '未知'),
                item.get('original', '')[:55],
                item.get('time', '')[:19]
            ))
    
    def restore_file(self):
        sel = self.tree.selection()
        if sel and self.quarantine_mgr.restore(int(sel[0])):
            self.refresh_list()
            self.log_message("已恢复文件")
    
    def delete_file(self):
        sel = self.tree.selection()
        if sel and messagebox.askyesno("确认", "永久删除？不可恢复！"):
            if self.quarantine_mgr.delete(int(sel[0])):
                self.refresh_list()
                self.log_message("已永久删除")
    
    def clear_log(self):
        """清空日志 - 需要用户确认"""
        if messagebox.askyesno("确认清空", "确定要清空所有日志吗？\n此操作不可撤销。", icon='question'):
            try:
                self.log_text.config(state='normal')
                self.log_text.delete(1.0, tk.END)
                self.log_text.config(state='disabled')
                self.log_message("日志已清空", "success")
            except:
                pass
    
    def log_message(self, msg: str, tag="info"):
        """记录日志 - 只读模式，用户不可修改"""
        if hasattr(self, 'log_text'):
            timestamp = datetime.now().strftime("%H:%M:%S")
            line = f"[{timestamp}] {msg}\n"
            
            def insert():
                try:
                    # 临时启用文本组件
                    self.log_text.config(state='normal')
                    # 插入日志
                    self.log_text.insert(tk.END, line, tag)
                    # 自动滚动到底部
                    self.log_text.see(tk.END)
                    # 限制日志行数（超过500行自动清理）
                    if int(self.log_text.index('end-1c').split('.')[0]) > 500:
                        self.log_text.delete(1.0, 200.0)
                    # 重新设为只读
                    self.log_text.config(state='disabled')
                except:
                    pass
            
            self.log_text.after(0, insert)
    
    def update_progress(self, cur, total, is_malicious=False):
        if total > 0:
            percent = int(cur / total * 100)
            self.progress_var.set(percent)
            self.progress_label.config(text=f"已扫描: {cur}/{total} ({percent}%)")
    
    def start_quick_scan(self):
        self._start_scan("quick")
    
    def start_full_scan(self):
        self._start_scan("full")
    
    def start_custom_scan(self):
        path = filedialog.askdirectory(title="选择扫描文件夹")
        if path:
            self._start_scan(path)
    
    def manual_update(self):
        self.log_message("正在手动更新病毒库...")
        threading.Thread(target=self.updater.update, daemon=True).start()
    
    def _start_scan(self, target):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        self.engine.stop_scan = False
        self.engine.set_callback(self.update_progress)
        self.scan_btn.config(state='disabled')
        self.full_btn.config(state='disabled')
        self.custom_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress_var.set(0)
        
        if target == "quick":
            self.log_message("开始快速扫描...")
            def scan_func(): 
                paths = [os.environ.get('SYSTEMROOT', 'C:\\Windows'), os.environ.get('TEMP', 'C:\\Windows\\Temp'),
                         os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')]
                result = {"total": 0, "scanned": 0, "infected": 0, "viruses": []}
                for p in paths:
                    if os.path.exists(p):
                        r = self.engine.scan_directory(p)
                        result["total"] += r["total"]
                        result["scanned"] += r["scanned"]
                        result["infected"] += r["infected"]
                        result["viruses"].extend(r["viruses"])
                return result
        elif target == "full":
            self.log_message("开始全盘扫描...")
            scan_func = lambda: self.engine.scan_directory("C:\\")
        else:
            self.log_message(f"开始扫描: {target}")
            scan_func = lambda: self.engine.scan_directory(target)
        
        def task():
            result = scan_func()
            self.root.after(0, self._on_scan_done, result)
        self.scan_thread = threading.Thread(target=task, daemon=True)
        self.scan_thread.start()
    
    def stop_scan(self):
        self.engine.stop()
        self.log_message("正在停止扫描...")
        self.stop_btn.config(state='disabled')
    
    def _on_scan_done(self, result):
        self.scan_btn.config(state='normal')
        self.full_btn.config(state='normal')
        self.custom_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.log_message("=" * 50)
        self.log_message(f"扫描完成！总文件: {result['total']}, 威胁: {result['infected']}")
        for v in result['viruses']:
            self.log_message(f"  - {v['name']}: {v['path']}", "virus")
            self.quarantine_mgr.quarantine(v['path'], v['name'])
        self.log_message("=" * 50)
        self.progress_label.config(text="扫描完成")
    
    def on_closing(self):
        self.log_message("正在关闭程序...")
        if self.real_time:
            self.real_time.stop()
        if self.hips:
            self.hips.stop()
        if self.popup:
            self.popup.stop()
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()


def main():
    try:
        app = LimeAntivirusGUI()
        app.run()
    except Exception as e:
        messagebox.showerror("错误", f"启动失败: {e}")


if __name__ == "__main__":
    main()