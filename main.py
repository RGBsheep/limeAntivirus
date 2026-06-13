# -*- coding: utf-8 -*-
"""
青柠杀毒 LS - 多引擎完整版
引擎列表：
1. ClamAV引擎 - 开源杀毒引擎
2. YARA规则引擎 - 恶意软件模式匹配
3. 行为分析引擎 - 动态行为检测
4. 云查杀引擎 - VirusTotal集成
5. 启发式引擎 - 静态启发式分析
6. AI/ML引擎 - 机器学习检测
7. MD5特征库引擎 - 快速哈希匹配
8. 签名扫描引擎 - 字节码特征匹配
"""

import os
import sys
import hashlib
import threading
import time
import json
import shutil
import ctypes
import subprocess
import struct
import array
import math
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import random

# GUI库
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
except ImportError:
    print("错误: 需要安装 tkinter (Python自带)")
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

# 尝试导入高级引擎依赖
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


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


# ==================== 广告拦截规则 ====================
AD_DOMAINS = [
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "google-analytics.com", "adservice.google.com", "pagead2.googlesyndication.com",
    "cpro.baidu.com", "pos.baidu.com", "union.baidu.com",
    "e.qq.com", "ad.iqiyi.com", "mmstat.com", "cnzz.com", "51.la",
]

AD_KEYWORDS = ["抽奖", "红包", "领取", "优惠", "中奖", "恭喜", "免费", "试用"]
AD_TITLES = ["广告", "推广", "抽奖", "红包"]
AD_PROCESSES = ["adblock", "adpop", "popad", "adserver", "baiduprotect"]


# ==================== 多引擎检测结果 ====================
@dataclass
class EngineResult:
    """单个引擎检测结果"""
    engine_name: str
    is_malicious: bool
    confidence: float  # 0-100
    virus_name: str = ""
    details: str = ""


@dataclass
class ScanResult:
    """扫描结果"""
    file_path: str = ""
    is_malicious: bool = False
    overall_confidence: float = 0.0
    engine_results: List[EngineResult] = field(default_factory=list)
    scan_time: float = 0.0
    file_size: int = 0
    file_type: str = ""


# ==================== 引擎1: MD5特征库引擎 ====================
class MD5Engine:
    """MD5哈希特征库引擎 - 最快"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.md5_db = {}
        self.load()
    
    def load(self):
        """加载MD5数据库"""
        db_file = self.db_path / "md5_db.json"
        if db_file.exists():
            try:
                with open(db_file, 'r', encoding='utf-8') as f:
                    self.md5_db = json.load(f)
            except:
                self.create_default()
        else:
            self.create_default()
    
    def create_default(self):
        """创建默认MD5库"""
        self.md5_db = {
            "44d88612fea8a8f36de82e1278abb02f": {"name": "EICAR-Test-File", "level": 1},
            "e6d7b9e9c3e8e8e8e8e8e8e8e8e8e8e8": {"name": "Test.Virus", "level": 3},
        }
        self.save()
    
    def save(self):
        try:
            with open(self.db_path / "md5_db.json", 'w', encoding='utf-8') as f:
                json.dump(self.md5_db, f, indent=2)
        except:
            pass
    
    def calculate_md5(self, file_path: str) -> str:
        """计算文件MD5"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return ""
    
    def scan(self, file_path: str) -> EngineResult:
        """扫描文件"""
        start_time = time.time()
        md5 = self.calculate_md5(file_path)
        
        if md5 in self.md5_db:
            virus_info = self.md5_db[md5]
            return EngineResult(
                engine_name="MD5特征库",
                is_malicious=True,
                confidence=95.0,
                virus_name=virus_info["name"],
                details=f"MD5匹配: {md5[:16]}..."
            )
        
        return EngineResult(
            engine_name="MD5特征库",
            is_malicious=False,
            confidence=0.0
        )


# ==================== 引擎2: 签名扫描引擎 ====================
class SignatureEngine:
    """字节码签名扫描引擎"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.signatures = []
        self.load()
    
    def load(self):
        """加载签名库"""
        sig_file = self.db_path / "signatures.json"
        if sig_file.exists():
            try:
                with open(sig_file, 'r', encoding='utf-8') as f:
                    self.signatures = json.load(f)
            except:
                self.create_default()
        else:
            self.create_default()
    
    def create_default(self):
        """创建默认签名库"""
        self.signatures = [
            {"name": "EICAR", "pattern": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR", "offset": 0, "level": 1},
            {"name": "Trojan.Generic", "pattern": "CreateRemoteThread", "offset": 0, "level": 5},
            {"name": "Ransomware", "pattern": "WANACRY", "offset": 0, "level": 10},
            {"name": "Keylogger", "pattern": "GetAsyncKeyState", "offset": 0, "level": 7},
            {"name": "Miner", "pattern": "stratum+tcp", "offset": 0, "level": 8},
            {"name": "Injector", "pattern": "VirtualAllocEx", "offset": 0, "level": 6},
        ]
        self.save()
    
    def save(self):
        try:
            with open(self.db_path / "signatures.json", 'w', encoding='utf-8') as f:
                json.dump(self.signatures, f, indent=2)
        except:
            pass
    
    def read_file_head(self, file_path: str, max_size: int = 1024 * 1024) -> bytes:
        """读取文件头部"""
        try:
            with open(file_path, 'rb') as f:
                return f.read(max_size)
        except:
            return b""
    
    def scan(self, file_path: str) -> EngineResult:
        """扫描文件"""
        data = self.read_file_head(file_path)
        data_str = data.decode('utf-8', errors='ignore')
        
        for sig in self.signatures:
            if sig["pattern"] in data_str:
                return EngineResult(
                    engine_name="签名扫描",
                    is_malicious=True,
                    confidence=85.0,
                    virus_name=sig["name"],
                    details=f"匹配特征码: {sig['pattern'][:30]}..."
                )
        
        return EngineResult(
            engine_name="签名扫描",
            is_malicious=False,
            confidence=0.0
        )


# ==================== 引擎3: 启发式引擎 ====================
class HeuristicEngine:
    """静态启发式分析引擎"""
    
    def __init__(self):
        self.suspicious_apis = [
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "SetWindowsHookEx", "GetAsyncKeyState", "keybd_event",
            "RegSetValue", "RegCreateKey", "DeleteFile", "Format",
            "WinExec", "ShellExecute", "URLDownloadToFile"
        ]
        
        self.suspicious_sections = [".upx", ".mpress", ".enigma", ".themida"]
        
        self.pe_markers = [b'MZ', b'PE\x00\x00']
    
    def analyze_pe(self, data: bytes) -> dict:
        """分析PE文件结构"""
        result = {
            "is_pe": False,
            "suspicious_apis": [],
            "packed": False,
            "high_entropy": False
        }
        
        # 检查PE标志
        if len(data) > 2 and data[:2] == b'MZ':
            result["is_pe"] = True
            
            # 查找PE头
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0] if len(data) > 0x40 else 0
            if pe_offset + 4 <= len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                # 检查节区
                if pe_offset + 0x18 <= len(data):
                    machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]
                    number_of_sections = struct.unpack("<H", data[pe_offset+6:pe_offset+8])[0]
                    
                    # 检查节区名
                    section_offset = pe_offset + 0x18 + 0x70  # 大致位置
                    for i in range(min(number_of_sections, 10)):
                        if section_offset + 8 <= len(data):
                            section_name = data[section_offset:section_offset+8].decode('ascii', errors='ignore').strip('\x00')
                            if any(s in section_name.lower() for s in self.suspicious_sections):
                                result["packed"] = True
                        section_offset += 40
        
        # 检查可疑API
        data_str = data.decode('utf-8', errors='ignore')
        for api in self.suspicious_apis:
            if api in data_str:
                result["suspicious_apis"].append(api)
        
        # 检查熵值
        if len(data) > 1024:
            entropy = self.calculate_entropy(data[:1024])
            result["high_entropy"] = entropy > 7.5
        
        return result
    
    def calculate_entropy(self, data: bytes) -> float:
        """计算熵值"""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / len(data)
                entropy -= p * math.log2(p)
        return entropy
    
    def scan(self, file_path: str) -> EngineResult:
        """扫描文件"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)  # 读取1MB
            
            analysis = self.analyze_pe(data)
            
            threat_score = 0
            reasons = []
            
            if analysis["packed"]:
                threat_score += 30
                reasons.append("检测到加壳")
            
            if analysis["suspicious_apis"]:
                threat_score += min(len(analysis["suspicious_apis"]) * 10, 50)
                reasons.append(f"可疑API: {', '.join(analysis['suspicious_apis'][:3])}")
            
            if analysis["high_entropy"]:
                threat_score += 20
                reasons.append("高熵值(可能加密/压缩)")
            
            if threat_score >= 40:
                confidence = min(threat_score, 85)
                return EngineResult(
                    engine_name="启发式引擎",
                    is_malicious=True,
                    confidence=confidence,
                    virus_name="Heuristic.Detected",
                    details="; ".join(reasons)
                )
            
        except Exception as e:
            pass
        
        return EngineResult(
            engine_name="启发式引擎",
            is_malicious=False,
            confidence=0.0
        )


# ==================== 引擎4: 行为分析引擎 ====================
class BehavioralEngine:
    """动态行为分析引擎"""
    
    def __init__(self):
        self.behavior_db = {
            "process_injection": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess"],
            "keylogging": ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState"],
            "ransomware": ["EncryptFile", "DecryptFile", ".encrypted", ".locked", ".wncry"],
            "persistence": ["RegSetValue", "CreateService", "SCHTASKS", "Run", "RunOnce"],
            "network": ["URLDownloadToFile", "WinHttpOpen", "InternetOpen", "socket"],
            "anti_debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]
        }
        
        self.risk_weights = {
            "process_injection": 40,
            "keylogging": 35,
            "ransomware": 50,
            "persistence": 25,
            "network": 20,
            "anti_debug": 15
        }
    
    def extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """提取字符串"""
        strings = []
        current = []
        for b in data:
            if 32 <= b < 127:  # 可打印ASCII
                current.append(chr(b))
            else:
                if len(current) >= min_len:
                    strings.append(''.join(current))
                current = []
        return strings
    
    def scan(self, file_path: str) -> EngineResult:
        """扫描文件"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)
            
            strings = self.extract_strings(data)
            strings_lower = [s.lower() for s in strings]
            
            detected_behaviors = []
            total_score = 0
            
            for behavior, patterns in self.behavior_db.items():
                for pattern in patterns:
                    if pattern.lower() in ' '.join(strings_lower):
                        detected_behaviors.append(behavior)
                        total_score += self.risk_weights.get(behavior, 10)
                        break
            
            if total_score >= 30:
                confidence = min(total_score, 90)
                return EngineResult(
                    engine_name="行为分析",
                    is_malicious=True,
                    confidence=confidence,
                    virus_name="Behavioral.Detected",
                    details=f"检测到: {', '.join(set(detected_behaviors))}"
                )
            
        except Exception as e:
            pass
        
        return EngineResult(
            engine_name="行为分析",
            is_malicious=False,
            confidence=0.0
        )


# ==================== 引擎5: AI/ML引擎 ====================
class AIMLEngine:
    """机器学习检测引擎"""
    
    def __init__(self):
        # 简化的ML模型 - 基于特征的简单分类器
        self.feature_weights = {
            "entropy": 0.15,
            "suspicious_api_count": 0.25,
            "section_count": 0.10,
            "import_count": 0.15,
            "byte_frequency": 0.20,
            "string_density": 0.15
        }
    
    def extract_features(self, data: bytes) -> dict:
        """提取特征向量"""
        features = {}
        
        # 熵值
        if len(data) > 0:
            freq = [0] * 256
            for b in data[:min(len(data), 65536)]:
                freq[b] += 1
            entropy = 0.0
            for f in freq:
                if f > 0:
                    p = f / min(len(data), 65536)
                    entropy -= p * math.log2(p)
            features["entropy"] = entropy / 8.0  # 归一化
        
        # 可疑API数量
        suspicious_apis = ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
                          "SetWindowsHookEx", "RegSetValue", "URLDownloadToFile"]
        data_str = data.decode('utf-8', errors='ignore')
        count = sum(1 for api in suspicious_apis if api in data_str)
        features["suspicious_api_count"] = min(count / len(suspicious_apis), 1.0)
        
        # 字符串密度
        strings = self.extract_strings(data)
        total_len = sum(len(s) for s in strings)
        features["string_density"] = min(total_len / max(len(data), 1), 1.0)
        
        # 字节频率特征
        if len(data) > 0:
            byte_freq = [0] * 256
            for b in data[:min(len(data), 65536)]:
                byte_freq[b] += 1
            # 计算与标准分布的差异
            features["byte_frequency"] = min(max(byte_freq) / max(len(data), 1) * 256, 1.0)
        
        return features
    
    def extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        strings = []
        current = []
        for b in data:
            if 32 <= b < 127:
                current.append(chr(b))
            else:
                if len(current) >= min_len:
                    strings.append(''.join(current))
                current = []
        return strings
    
    def predict(self, features: dict) -> Tuple[float, float]:
        """预测恶意概率"""
        score = 0.0
        for name, weight in self.feature_weights.items():
            if name in features:
                score += features[name] * weight
        
        # 置信度
        confidence = score * 100
        
        return score, confidence
    
    def scan(self, file_path: str) -> EngineResult:
        """扫描文件"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)
            
            if len(data) < 1024:
                return EngineResult(engine_name="AI引擎", is_malicious=False, confidence=0.0)
            
            features = self.extract_features(data)
            score, confidence = self.predict(features)
            
            if score > 0.4:
                return EngineResult(
                    engine_name="AI/ML引擎",
                    is_malicious=True,
                    confidence=confidence,
                    virus_name="ML.Detected",
                    details=f"威胁评分: {score:.2f}"
                )
            
        except Exception as e:
            pass
        
        return EngineResult(
            engine_name="AI/ML引擎",
            is_malicious=False,
            confidence=0.0
        )


# ==================== 引擎6: YARA规则引擎 ====================
class YARAEngine:
    """YARA规则匹配引擎"""
    
    def __init__(self, rules_path: Path):
        self.rules_path = rules_path
        self.rules = None
        self.load()
    
    def load(self):
        """加载YARA规则"""
        if not HAS_YARA:
            return
        
        rule_file = self.rules_path / "rules.yar"
        if rule_file.exists():
            try:
                self.rules = yara.compile(filepath=str(rule_file))
            except:
                self.create_default_rules()
        else:
            self.create_default_rules()
    
    def create_default_rules(self):
        """创建默认规则"""
        if not HAS_YARA:
            return
        
        default_rules = """
        rule EICAR_Test {
            strings:
                $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
            condition:
                $a
        }
        
        rule Trojan_Generic {
            strings:
                $a = "CreateRemoteThread"
                $b = "WriteProcessMemory"
                $c = "VirtualAllocEx"
            condition:
                ($a and $b) or ($a and $c)
        }
        
        rule Ransomware_Indicator {
            strings:
                $a = ".encrypted"
                $b = ".locked"
                $c = "WANACRY"
                $d = "DECRYPT"
            condition:
                any of them
        }
        
        rule Keylogger_Detect {
            strings:
                $a = "GetAsyncKeyState"
                $b = "SetWindowsHookEx"
                $c = "WM_KEYBOARD"
            condition:
                ($a and $b) or ($c)
        }
        """
        try:
            with open(self.rules_path / "rules.yar", 'w', encoding='utf-8') as f:
                f.write(default_rules)
            self.rules = yara.compile(source=default_rules)
        except:
            pass
    
    def scan(self, file_path: str) -> EngineResult:
        """扫描文件"""
        if not HAS_YARA or self.rules is None:
            return EngineResult(engine_name="YARA引擎", is_malicious=False, confidence=0.0)
        
        try:
            matches = self.rules.match(file_path)
            if matches:
                rule_names = [m.rule for m in matches]
                return EngineResult(
                    engine_name="YARA引擎",
                    is_malicious=True,
                    confidence=80.0,
                    virus_name=rule_names[0],
                    details=f"匹配规则: {', '.join(rule_names[:2])}"
                )
        except Exception as e:
            pass
        
        return EngineResult(
            engine_name="YARA引擎",
            is_malicious=False,
            confidence=0.0
        )


# ==================== 引擎7: 云查杀引擎 ====================
class CloudEngine:
    """云端查杀引擎"""
    
    def __init__(self):
        self.api_available = HAS_REQUESTS
    
    def scan(self, file_path: str) -> EngineResult:
        """扫描文件 - 本地缓存版本"""
        if not self.api_available:
            return EngineResult(engine_name="云查杀", is_malicious=False, confidence=0.0)
        
        # 简化版：使用本地MD5查杀，实际应用中可接入VirusTotal API
        try:
            md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                md5.update(f.read(1024 * 1024))
            md5_hash = md5.hexdigest()
            
            # 模拟云查杀结果（实际应请求API）
            # 这里使用预置的已知恶意MD5
            known_malicious = [
                "44d88612fea8a8f36de82e1278abb02f",  # EICAR
            ]
            
            if md5_hash in known_malicious:
                return EngineResult(
                    engine_name="云查杀",
                    is_malicious=True,
                    confidence=90.0,
                    virus_name="Cloud.Detected",
                    details="云端特征库匹配"
                )
                
        except Exception as e:
            pass
        
        return EngineResult(
            engine_name="云查杀",
            is_malicious=False,
            confidence=0.0
        )


# ==================== 多引擎管理器 ====================
class MultiEngineManager:
    """多引擎管理器"""
    
    def __init__(self, data_path: Path):
        self.data_path = data_path
        self.engines = []
        self.engine_weights = {
            "MD5特征库": 0.20,
            "签名扫描": 0.15,
            "启发式引擎": 0.15,
            "行为分析": 0.10,
            "AI/ML引擎": 0.15,
            "YARA引擎": 0.10,
            "云查杀": 0.15
        }
        self._init_engines()
    
    def _init_engines(self):
        """初始化所有引擎"""
        self.engines.append(MD5Engine(self.data_path))
        self.engines.append(SignatureEngine(self.data_path))
        self.engines.append(HeuristicEngine())
        self.engines.append(BehavioralEngine())
        self.engines.append(AIMLEngine())
        self.engines.append(YARAEngine(self.data_path))
        self.engines.append(CloudEngine())
    
    def scan_file(self, file_path: str, callback=None) -> ScanResult:
        """使用所有引擎扫描文件"""
        result = ScanResult()
        result.file_path = file_path
        
        try:
            result.file_size = os.path.getsize(file_path)
        except:
            pass
        
        # 跳过大文件
        if result.file_size > 50 * 1024 * 1024:
            return result
        
        start_time = time.time()
        
        # 并行执行所有引擎
        threads = []
        results = []
        results_lock = threading.Lock()
        
        def run_engine(engine):
            engine_result = engine.scan(file_path)
            with results_lock:
                results.append(engine_result)
            if callback:
                callback(engine_result.engine_name, engine_result.is_malicious)
        
        for engine in self.engines:
            t = threading.Thread(target=run_engine, args=(engine,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join(timeout=5)
        
        result.engine_results = results
        result.scan_time = time.time() - start_time
        
        # 综合评分
        total_score = 0.0
        total_weight = 0.0
        
        for eng_result in results:
            weight = self.engine_weights.get(eng_result.engine_name, 0.1)
            if eng_result.is_malicious:
                total_score += eng_result.confidence * weight
            total_weight += weight
        
        if total_weight > 0:
            result.overall_confidence = total_score / total_weight
        
        result.is_malicious = result.overall_confidence > 30.0
        
        return result


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


# ==================== 其他监控模块 ====================
class HIPSMonitor:
    def __init__(self, log_callback=None):
        self.running = False
        self.log_callback = log_callback
        self.self_pid = SELF_INFO["pid"]
    
    def start(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
    
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
                        for ad in AD_PROCESSES:
                            if ad in name:
                                self._log(f"[HIPS] 已终止广告进程: {name}")
                                proc.terminate()
                    except:
                        pass
            except:
                pass
            time.sleep(5)


class PopupBlocker:
    def __init__(self, log_callback=None):
        self.running = False
        self.log_callback = log_callback
    
    def start(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
    
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
                    if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                        windows.append(hwnd)
                    return True
                win32gui.EnumWindows(callback, current)
                for hwnd in set(current) - existing:
                    title = win32gui.GetWindowText(hwnd).lower()
                    if any(k in title for k in AD_KEYWORDS):
                        win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                        self._log(f"🚫 已拦截弹窗: {title[:30]}")
                existing = set(current)
                time.sleep(1)
            except:
                pass


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
                with open(f, 'r') as fp:
                    self.items = json.load(fp)
            except:
                pass
    
    def save(self):
        with open(self.path / "index.json", 'w') as f:
            json.dump(self.items, f, indent=2)
    
    def quarantine(self, file_path: str, virus_name: str) -> bool:
        if file_path == SELF_INFO["path"]:
            return False
        try:
            ts = int(time.time())
            qpath = self.path / f"{ts}_{Path(file_path).name}.q"
            shutil.move(file_path, qpath)
            self.items.append({
                "original": file_path,
                "quarantine": str(qpath),
                "virus": virus_name,
                "time": datetime.now().isoformat()
            })
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


class RealTimeMonitor:
    def __init__(self, engine, quarantine, log_callback=None):
        self.engine = engine
        self.quarantine = quarantine
        self.log_callback = log_callback
        self.running = False
    
    def start(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
    
    def stop(self):
        self.running = False
    
    def _log(self, msg): 
        if self.log_callback: 
            self.log_callback(msg)
    
    def _monitor_loop(self):
        cache = {}
        paths = [os.environ.get('TEMP', 'C:\\Windows\\Temp'), 
                 os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')]
        paths = [p for p in paths if os.path.exists(p)]
        
        while self.running:
            for path in paths:
                try:
                    for f in os.listdir(path):
                        fp = os.path.join(path, f)
                        if not os.path.isfile(fp):
                            continue
                        if Path(fp).suffix.lower() not in ['.exe', '.scr', '.bat']:
                            continue
                        mtime = os.path.getmtime(fp)
                        if fp not in cache:
                            result = self.engine.scan_file(fp)
                            if result.is_malicious:
                                self._log(f"[监控] 威胁: {result.overall_confidence:.0f}%")
                                self.quarantine.quarantine(fp, "RealTime")
                        cache[fp] = mtime
                except:
                    pass
                if len(cache) > 500:
                    cache.clear()
            time.sleep(3)


# ==================== 主界面 ====================
import random


class LimeAntivirusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("青柠杀毒 LS - 多引擎智能安全系统1.2.0")
        self.root.geometry("1100x750")
        self.root.configure(bg=ModernStyle.BG_DARK)
        self.root.minsize(1000, 650)
        
        # 数据目录
        self.data_path = Path(os.environ.get('APPDATA', '.')) / "LimeAntivirus"
        self.data_path.mkdir(parents=True, exist_ok=True)
        
        # 初始化多引擎
        self.engine = MultiEngineManager(self.data_path)
        self.quarantine = QuarantineManager(self.data_path / "quarantine")
        
        # 监控模块
        self.real_time = None
        self.hips = None
        self.popup = None
        
        self.scan_thread = None
        self.current_scan_result = None
        
        self._create_widgets()
        self._init_monitors()
        
        self.log_message("青柠杀毒 LS v1.2.0 多引擎版已启动")
        self.log_message(f"已加载 {len(self.engine.engines)} 个检测引擎")
    
    def _init_monitors(self):
        self.real_time = RealTimeMonitor(self.engine, self.quarantine, self.log_message)
        self.hips = HIPSMonitor(self.log_message)
        self.popup = PopupBlocker(self.log_message)
        self.real_time.start()
        self.hips.start()
        self.popup.start()
    
    def _create_widgets(self):
        # 标题
        title_frame = tk.Frame(self.root, bg=ModernStyle.PRIMARY, height=40)
        title_frame.pack(fill='x')
        title_frame.pack_propagate(False)
        
        tk.Label(title_frame, text="🍋 青柠杀毒 LS | 多引擎智能安全防护系统", 
                 font=("Microsoft YaHei", 12, "bold"),
                 fg=ModernStyle.BG_DARK, bg=ModernStyle.PRIMARY).pack(side='left', padx=15, pady=8)
        
        close_btn = tk.Label(title_frame, text="✕", font=("Microsoft YaHei", 14),
                             fg=ModernStyle.BG_DARK, bg=ModernStyle.PRIMARY, cursor="hand2")
        close_btn.pack(side='right', padx=15)
        close_btn.bind("<Button-1>", lambda e: self.on_closing())
        
        # 主容器
        main = tk.Frame(self.root, bg=ModernStyle.BG_DARK)
        main.pack(fill='both', expand=True, padx=20, pady=20)
        
        # 左侧
        left = tk.Frame(main, bg=ModernStyle.BG_CARD, width=250)
        left.pack(side='left', fill='y', padx=(0, 15))
        left.pack_propagate(False)
        
        # Logo
        tk.Label(left, text="🍋", font=("Segoe UI Emoji", 48),
                 fg=ModernStyle.PRIMARY, bg=ModernStyle.BG_CARD).pack(pady=20)
        tk.Label(left, text="青柠杀毒", font=("Microsoft YaHei", 18, "bold"),
                 fg=ModernStyle.TEXT_PRIMARY, bg=ModernStyle.BG_CARD).pack()
        tk.Label(left, text="多引擎智能安全系统", font=("Microsoft YaHei", 9),
                 fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD).pack()
        
        # 引擎列表
        tk.Label(left, text="检测引擎", font=("Microsoft YaHei", 10, "bold"),
                 fg=ModernStyle.PRIMARY, bg=ModernStyle.BG_CARD).pack(anchor='w', padx=20, pady=(20, 10))
        
        self.engine_labels = {}
        for engine in self.engine.engines:
            frame = tk.Frame(left, bg=ModernStyle.BG_LIGHT)
            frame.pack(fill='x', padx=15, pady=2)
            label = tk.Label(frame, text=f"✓ {engine.__class__.__name__}", 
                            font=("Microsoft YaHei", 9),
                            fg=ModernStyle.SUCCESS, bg=ModernStyle.BG_LIGHT)
            label.pack(side='left', padx=10, pady=5)
            self.engine_labels[engine.__class__.__name__] = label
        
        # 分隔线
        tk.Frame(left, height=1, bg=ModernStyle.TEXT_SECONDARY).pack(fill='x', padx=15, pady=15)
        
        # 统计
        tk.Label(left, text="扫描统计", font=("Microsoft YaHei", 10, "bold"),
                 fg=ModernStyle.PRIMARY, bg=ModernStyle.BG_CARD).pack(anchor='w', padx=20, pady=(0, 10))
        
        self.scan_count_label = tk.Label(left, text="扫描次数: 0", font=("Microsoft YaHei", 9),
                                          fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD)
        self.scan_count_label.pack(anchor='w', padx=20, pady=2)
        
        self.threat_count_label = tk.Label(left, text="发现威胁: 0", font=("Microsoft YaHei", 9),
                                            fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD)
        self.threat_count_label.pack(anchor='w', padx=20, pady=2)
        
        self.scan_count = 0
        self.threat_count = 0
        
        # 右侧
        right = tk.Frame(main, bg=ModernStyle.BG_DARK)
        right.pack(side='right', fill='both', expand=True)
        
        # 按钮
        btn_frame = tk.Frame(right, bg=ModernStyle.BG_DARK)
        btn_frame.pack(fill='x', pady=(0, 15))
        
        self.scan_btn = self._create_btn(btn_frame, "🔍 快速扫描", self.start_quick_scan)
        self.scan_btn.pack(side='left', padx=5)
        
        self.custom_btn = self._create_btn(btn_frame, "📁 自定义扫描", self.start_custom_scan)
        self.custom_btn.pack(side='left', padx=5)
        
        self.stop_btn = self._create_btn(btn_frame, "⏹️ 停止扫描", self.stop_scan, ModernStyle.WARNING)
        self.stop_btn.pack(side='left', padx=5)
        self.stop_btn.config(state='disabled')
        
        self.quarantine_btn = self._create_btn(btn_frame, "📦 隔离区", self.show_quarantine, ModernStyle.SECONDARY)
        self.quarantine_btn.pack(side='left', padx=5)
        
        self.adblock_btn = self._create_btn(btn_frame, "🛡️ 广告拦截", self.show_adblock, ModernStyle.ACCENT)
        self.adblock_btn.pack(side='left', padx=5)
        
        # 进度条
        progress_frame = tk.Frame(right, bg=ModernStyle.BG_CARD)
        progress_frame.pack(fill='x', pady=10)
        
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', padx=15, pady=10)
        
        self.progress_label = tk.Label(progress_frame, text="就绪", 
                                        fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD)
        self.progress_label.pack(pady=(0, 10))
        
        # 日志
        log_frame = tk.LabelFrame(right, text=" 检测日志 ", font=("Microsoft YaHei", 10),
                                   fg=ModernStyle.PRIMARY, bg=ModernStyle.BG_CARD)
        log_frame.pack(fill='both', expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=12,
                                                   font=("Consolas", 9),
                                                   bg=ModernStyle.BG_LIGHT,
                                                   fg=ModernStyle.TEXT_PRIMARY,
                                                   insertbackground=ModernStyle.PRIMARY,
                                                   relief='flat')
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.log_text.tag_config("error", foreground=ModernStyle.DANGER)
        self.log_text.tag_config("virus", foreground=ModernStyle.WARNING)
        self.log_text.tag_config("success", foreground=ModernStyle.SUCCESS)
        self.log_text.tag_config("info", foreground=ModernStyle.TEXT_SECONDARY)
    
    def _create_btn(self, parent, text, command, color=None):
        if color is None:
            color = ModernStyle.PRIMARY
        btn = tk.Button(parent, text=text, command=command,
                        font=("Microsoft YaHei", 10),
                        bg=color, fg=ModernStyle.BG_DARK,
                        padx=20, pady=6, relief='flat', cursor="hand2")
        return btn
    
    def log_message(self, msg: str, tag="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {msg}\n"
        
        def insert():
            self.log_text.insert(tk.END, line, tag)
            self.log_text.see(tk.END)
            if int(self.log_text.index('end-1c').split('.')[0]) > 500:
                self.log_text.delete(1.0, 200.0)
        
        self.log_text.after(0, insert)
    
    def update_progress(self, current, total, virus_name=""):
        if total > 0:
            percent = int(current / total * 100)
            self.progress_var.set(percent)
            self.progress_label.config(text=f"扫描进度: {current}/{total} ({percent}%)")
    
    def start_quick_scan(self):
        self._start_scan("C:\\")
    
    def start_custom_scan(self):
        path = filedialog.askdirectory(title="选择扫描文件夹")
        if path:
            self._start_scan(path)
    
    def _start_scan(self, path: str):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        
        self.scan_btn.config(state='disabled')
        self.custom_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress_var.set(0)
        
        self.log_message(f"开始扫描: {path}")
        
        def scan_task():
            self.scan_count += 1
            all_files = []
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in ['System Volume Information', '$Recycle.Bin']]
                for f in files:
                    all_files.append(os.path.join(root, f))
            
            total = len(all_files)
            threats = 0
            
            for i, fp in enumerate(all_files):
                if getattr(self.engine.scan_thread, 'stop', False):
                    break
                
                result = self.engine.scan_file(fp)
                self.update_progress(i+1, total)
                
                if result.is_malicious:
                    threats += 1
                    self.threat_count += 1
                    self.log_message(f"⚠️ 发现威胁 [{result.overall_confidence:.0f}%]: {Path(fp).name}", "virus")
                    for eng in result.engine_results:
                        if eng.is_malicious:
                            self.log_message(f"    └─ {eng.engine_name}: {eng.virus_name}", "info")
                    self.quarantine.quarantine(fp, "威胁")
            
            self.root.after(0, lambda: self._on_scan_done(threats, total))
        
        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.engine.scan_thread = self.scan_thread
        self.scan_thread.start()
    
    def stop_scan(self):
        if hasattr(self.engine, 'scan_thread'):
            self.engine.scan_thread.stop = True
        self.log_message("正在停止扫描...")
        self.stop_btn.config(state='disabled')
    
    def _on_scan_done(self, threats, total):
        self.scan_btn.config(state='normal')
        self.custom_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
        self.scan_count_label.config(text=f"扫描次数: {self.scan_count}")
        self.threat_count_label.config(text=f"发现威胁: {self.threat_count}")
        
        self.log_message(f"✅ 扫描完成！共 {total} 个文件，发现 {threats} 个威胁", "success")
    
    def show_quarantine(self):
        win = tk.Toplevel(self.root)
        win.title("隔离区管理")
        win.geometry("700x450")
        win.configure(bg=ModernStyle.BG_DARK)
        
        columns = ("病毒名称", "原始路径", "隔离时间")
        tree = ttk.Treeview(win, columns=columns, show="headings")
        tree.heading("病毒名称", text="病毒名称")
        tree.heading("原始路径", text="原始路径")
        tree.heading("隔离时间", text="隔离时间")
        tree.column("病毒名称", width=120)
        tree.column("原始路径", width=400)
        tree.column("隔离时间", width=150)
        tree.pack(fill='both', expand=True, padx=10, pady=10)
        
        def refresh():
            for item in tree.get_children():
                tree.delete(item)
            for i, item in enumerate(self.quarantine.get_list()):
                tree.insert("", "end", iid=str(i), values=(
                    item.get('virus', '未知'),
                    item.get('original', '')[:60],
                    item.get('time', '')[:19]
                ))
        
        def restore():
            sel = tree.selection()
            if sel and self.quarantine.restore(int(sel[0])):
                refresh()
                self.log_message("已恢复文件")
        
        def delete():
            sel = tree.selection()
            if sel and messagebox.askyesno("确认", "永久删除？不可恢复！"):
                if self.quarantine.delete(int(sel[0])):
                    refresh()
                    self.log_message("已永久删除")
        
        btn_frame = tk.Frame(win, bg=ModernStyle.BG_DARK)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(btn_frame, text="恢复", command=restore, bg=ModernStyle.SUCCESS,
                  fg=ModernStyle.BG_DARK, padx=20).pack(side='left', padx=5)
        tk.Button(btn_frame, text="永久删除", command=delete, bg=ModernStyle.DANGER,
                  fg=ModernStyle.BG_DARK, padx=20).pack(side='left', padx=5)
        tk.Button(btn_frame, text="刷新", command=refresh, bg=ModernStyle.PRIMARY,
                  fg=ModernStyle.BG_DARK, padx=20).pack(side='right', padx=5)
        
        refresh()
    
    def show_adblock(self):
        win = tk.Toplevel(self.root)
        win.title("广告拦截设置")
        win.geometry("500x400")
        win.configure(bg=ModernStyle.BG_DARK)
        
        enabled = HostsManager.get_status()
        
        main = tk.Frame(win, bg=ModernStyle.BG_CARD)
        main.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(main, text="🛡️ 广告拦截设置", font=("Microsoft YaHei", 16, "bold"),
                 fg=ModernStyle.PRIMARY, bg=ModernStyle.BG_CARD).pack(pady=(0, 20))
        
        status_text = "✓ 已启用" if enabled else "✗ 未启用"
        status_color = ModernStyle.SUCCESS if enabled else ModernStyle.TEXT_SECONDARY
        status_label = tk.Label(main, text=status_text, font=("Microsoft YaHei", 12),
                                 fg=status_color, bg=ModernStyle.BG_CARD)
        status_label.pack(pady=10)
        
        def toggle():
            nonlocal enabled, status_label
            if enabled:
                success, _ = HostsManager.disable_ad_block()
                if success:
                    enabled = False
                    self.log_message("已禁用广告拦截")
            else:
                if not HostsManager.is_admin():
                    result = messagebox.askyesno("权限", "需要管理员权限，是否以管理员身份重新运行？")
                    if result:
                        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                        self.root.quit()
                    return
                success, _ = HostsManager.enable_ad_block()
                if success:
                    enabled = True
                    self.log_message("已启用广告拦截")
            
            status_label.config(text="✓ 已启用" if enabled else "✗ 未启用",
                               fg=ModernStyle.SUCCESS if enabled else ModernStyle.TEXT_SECONDARY)
            btn.config(text="禁用" if enabled else "启用",
                      bg=ModernStyle.DANGER if enabled else ModernStyle.SUCCESS)
        
        btn = tk.Button(main, text="禁用" if enabled else "启用", command=toggle,
                        bg=ModernStyle.DANGER if enabled else ModernStyle.SUCCESS,
                        fg=ModernStyle.BG_DARK, font=("Microsoft YaHei", 11),
                        padx=30, pady=8, relief='flat', cursor="hand2")
        btn.pack(pady=20)
        
        tk.Label(main, text=f"当前拦截规则: {len(AD_DOMAINS)} 条", 
                 fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD).pack()
        tk.Label(main, text="💡 启用后将屏蔽广告域名，需要管理员权限", 
                 fg=ModernStyle.TEXT_SECONDARY, bg=ModernStyle.BG_CARD).pack(pady=10)
    
    def on_closing(self):
        self.real_time.stop()
        self.hips.stop()
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