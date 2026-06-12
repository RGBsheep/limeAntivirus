# -*- coding: utf-8 -*-
"""
青柠杀毒 LS - 1.1.4
功能：病毒扫描、实时监控、HIPS、隔离区、广告拦截
修复：不再拦截自己的窗口和进程
"""

import os
import sys
import hashlib
import threading
import time
import json
import shutil
import ctypes
import socket
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass

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


# ==================== 获取自身信息 ====================
def get_self_info():
    """获取自身进程信息，用于避免拦截自己"""
    try:
        self_pid = os.getpid()
        self_name = "main.py" if not getattr(sys, 'frozen', False) else "LimeAntivirus.exe"
        self_path = sys.argv[0] if sys.argv else ""
        return {
            "pid": self_pid,
            "name": self_name,
            "path": self_path
        }
    except:
        return {"pid": -1, "name": "", "path": ""}


SELF_INFO = get_self_info()


# ==================== 广告拦截规则 ====================
AD_DOMAINS = [
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "google-analytics.com", "adservice.google.com", "pagead2.googlesyndication.com",
    "googleads.g.doubleclick.net", "ad.doubleclick.net",
    "adbrite.com", "adnxs.com", "adzerk.net", "criteo.com", "outbrain.com",
    "taboola.com", "exoclick.com", "popads.net", "mgid.com", "adcash.com",
    "cpro.baidu.com", "pos.baidu.com", "union.baidu.com", "hm.baidu.com",
    "e.qq.com", "l.qq.com", "ad.iqiyi.com", "msg.iqiyi.com",
    "mmstat.com", "cnzz.com", "51.la", "yunjiasu-cdn.net", "tanx.com",
]

AD_KEYWORDS = [
    "抽奖", "红包", "领取", "优惠", "优惠券", "中奖", "恭喜", "幸运",
    "免费", "试用", "推广", "推荐", "赚钱", "兼职", "刷单",
    "lucky", "winner", "congratulations", "free", "discount", "coupon",
]

AD_TITLES = ["广告", "推广", "抽奖", "中奖", "红包"]

# 广告进程名（不包含自己）
AD_PROCESSES = [
    "adblock", "adpop", "popad", "adserver", "showad",
    "baiduprotect", "baidunetdisk"
]


# ==================== 白名单（包含自己）====================
class Whitelist:
    SYSTEM_PROCESSES = {
        'System', 'System Idle Process', 'svchost.exe', 'explorer.exe',
        'winlogon.exe', 'csrss.exe', 'services.exe', 'lsass.exe',
        'wininit.exe', 'spoolsv.exe', 'taskhost.exe', 'dwm.exe',
        'ctfmon.exe', 'sihost.exe', 'taskmgr.exe', 'regedit.exe',
        'cmd.exe', 'powershell.exe', 'notepad.exe', 'calc.exe',
        'msedge.exe', 'chrome.exe', 'firefox.exe', 
        'python.exe', 'pythonw.exe',
        'code.exe', 'devenv.exe', 'msbuild.exe',
        'LimeAntivirus.exe', 'main.py'
    }
    
    SYSTEM_PATHS = [
        r'C:\Windows\System32',
        r'C:\Windows\SysWOW64',
        r'C:\Program Files',
        r'C:\Program Files (x86)'
    ]
    
    @classmethod
    def is_self(cls, pid: int, name: str = "", path: str = "") -> bool:
        """检查是否为自己"""
        if pid == SELF_INFO["pid"]:
            return True
        if name and name.lower() in [n.lower() for n in ['main.py', 'limeantivirus.exe', 'pythonw.exe']]:
            if path and SELF_INFO["path"] and path == SELF_INFO["path"]:
                return True
        return False
    
    @classmethod
    def is_trusted(cls, process_name: str, process_path: str = "", pid: int = None) -> bool:
        """检查进程是否可信"""
        if pid is not None and cls.is_self(pid, process_name, process_path):
            return True
        
        if process_name.lower() in [p.lower() for p in cls.SYSTEM_PROCESSES]:
            return True
        
        if process_path:
            for sys_path in cls.SYSTEM_PATHS:
                if process_path.lower().startswith(sys_path.lower()):
                    return True
        
        return False
    
    @classmethod
    def is_system_path(cls, path: str) -> bool:
        for sys_path in cls.SYSTEM_PATHS:
            if path.lower().startswith(sys_path.lower()):
                return True
        return False


# ==================== Hosts文件管理 ====================
class HostsManager:
    HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
    BACKUP_PATH = r"C:\Windows\System32\drivers\etc\hosts.backup"
    
    @classmethod
    def is_admin(cls):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    @classmethod
    def backup(cls):
        try:
            if os.path.exists(cls.HOSTS_PATH):
                shutil.copy2(cls.HOSTS_PATH, cls.BACKUP_PATH)
                return True
        except:
            pass
        return False
    
    @classmethod
    def enable_ad_block(cls):
        if not cls.is_admin():
            return False, "需要管理员权限"
        
        try:
            cls.backup()
            
            with open(cls.HOSTS_PATH, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if "# LimeAntivirus AdBlock Start" in content:
                return False, "广告拦截已启用"
            
            with open(cls.HOSTS_PATH, 'a', encoding='utf-8') as f:
                f.write("\n\n# ========================================\n")
                f.write("# LimeAntivirus AdBlock Start\n")
                for domain in AD_DOMAINS:
                    f.write(f"0.0.0.0 {domain}\n")
                f.write("# LimeAntivirus AdBlock End\n")
                f.write("# ========================================\n")
            
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
            return True, f"已添加 {len(AD_DOMAINS)} 条拦截规则"
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
                if "# LimeAntivirus AdBlock Start" in line:
                    skip = True
                    continue
                if "# LimeAntivirus AdBlock End" in line:
                    skip = False
                    continue
                if not skip:
                    new_lines.append(line)
            
            with open(cls.HOSTS_PATH, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
            return True, "已禁用广告拦截"
        except Exception as e:
            return False, str(e)
    
    @classmethod
    def get_status(cls):
        try:
            with open(cls.HOSTS_PATH, 'r', encoding='utf-8') as f:
                content = f.read()
                return "# LimeAntivirus AdBlock Start" in content
        except:
            return False


# ==================== 病毒特征库 ====================
class VirusDatabase:
    def __init__(self, data_path: Path):
        self.data_path = data_path
        self.signatures = []
        self.md5_index = {}
        self.load()
    
    def load(self):
        db_file = self.data_path / "virusdb.json"
        if db_file.exists():
            try:
                with open(db_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.signatures = data.get('signatures', [])
                    self.rebuild_index()
            except:
                self.create_default()
        else:
            self.create_default()
    
    def create_default(self):
        self.signatures = [
            {"name": "EICAR-Test-File", "md5": "44d88612fea8a8f36de82e1278abb02f",
             "filenames": ["eicar.com", "eicar.com.txt"], 
             "patterns": ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"], "threat_level": 1},
            {"name": "Trojan.Generic", "md5": "", "filenames": ["svchost.exe.bak", "winupdate.exe"],
             "patterns": [], "threat_level": 5},
            {"name": "Ransomware.Generic", "md5": "", "filenames": ["wncry", "@wanadecryptor"],
             "patterns": ["WANACRY"], "threat_level": 10},
        ]
        self.rebuild_index()
        self.save()
    
    def rebuild_index(self):
        self.md5_index.clear()
        for sig in self.signatures:
            if sig.get('md5'):
                self.md5_index[sig['md5']] = sig
    
    def save(self):
        try:
            with open(self.data_path / "virusdb.json", 'w', encoding='utf-8') as f:
                json.dump({"signatures": self.signatures, "version": "2.0"}, f, indent=2)
        except:
            pass
    
    def match(self, file_path: str, md5: str, content: str = "") -> Tuple[str, int]:
        if md5 in self.md5_index:
            sig = self.md5_index[md5]
            return sig['name'], sig.get('threat_level', 5)
        
        filename = Path(file_path).name.lower()
        for sig in self.signatures:
            for pattern in sig.get('filenames', []):
                if pattern.lower() in filename:
                    return sig['name'], sig.get('threat_level', 5)
        
        if content:
            for sig in self.signatures:
                for pattern in sig.get('patterns', []):
                    if pattern in content:
                        return sig['name'], sig.get('threat_level', 5)
        
        return "", 0


# ==================== 扫描引擎 ====================
class ScanEngine:
    def __init__(self, virus_db: VirusDatabase):
        self.virus_db = virus_db
        self.stop_scan = False
        self.callback = None
    
    def set_callback(self, callback):
        self.callback = callback
    
    def calculate_md5(self, file_path: str) -> str:
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_md5.update(chunk)
                    if len(chunk) < 8192:
                        break
            return hash_md5.hexdigest()
        except:
            return ""
    
    def scan_file(self, file_path: str) -> Tuple[str, int]:
        # 跳过自身文件
        if file_path == SELF_INFO["path"]:
            return "", 0
        
        try:
            if os.path.getsize(file_path) > 50 * 1024 * 1024:
                return "", 0
        except:
            return "", 0
        
        if Whitelist.is_system_path(file_path):
            ext = Path(file_path).suffix.lower()
            if ext in ['.exe', '.dll'] and 'system32' in file_path.lower():
                return "", 0
        
        md5 = self.calculate_md5(file_path)
        return self.virus_db.match(file_path, md5, "")
    
    def scan_directory(self, path: str) -> ScanResult:
        result = ScanResult()
        all_files = []
        
        for root, dirs, files in os.walk(path):
            if self.stop_scan:
                break
            dirs[:] = [d for d in dirs if d not in ['System Volume Information', '$Recycle.Bin']]
            for file in files:
                all_files.append(os.path.join(root, file))
        
        result.total_files = len(all_files)
        
        for i, file_path in enumerate(all_files):
            if self.stop_scan:
                break
            
            virus_name, level = self.scan_file(file_path)
            result.scanned_files = i + 1
            
            if virus_name:
                result.infected_files += 1
                result.viruses.append(VirusInfo(
                    name=virus_name,
                    file_path=file_path,
                    md5=self.calculate_md5(file_path),
                    detect_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    threat_level=level
                ))
            
            if self.callback:
                self.callback(i + 1, result.total_files, virus_name)
        
        return result
    
    def stop(self):
        self.stop_scan = True


@dataclass
class VirusInfo:
    name: str
    file_path: str
    md5: str
    detect_time: str
    threat_level: int


@dataclass
class ScanResult:
    total_files: int = 0
    scanned_files: int = 0
    infected_files: int = 0
    viruses: List[VirusInfo] = None
    
    def __post_init__(self):
        if self.viruses is None:
            self.viruses = []


# ==================== HIPS监控（修复版 - 不拦截自己）====================
class HIPSMonitor:
    def __init__(self, log_callback=None):
        self.running = False
        self.thread = None
        self.log_callback = log_callback
        self.self_pid = SELF_INFO["pid"]
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        self._log("HIPS防护已启动")
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _log(self, msg: str, is_error: bool = False):
        if self.log_callback:
            self.log_callback(msg, is_error)
    
    def _monitor_loop(self):
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name'] or ''
                        exe = proc.info['exe'] or ''
                        
                        # 跳过自己
                        if pid == self.self_pid:
                            continue
                        if Whitelist.is_self(pid, name, exe):
                            continue
                        
                        # 检查广告进程
                        for ad_proc in AD_PROCESSES:
                            if ad_proc.lower() in name.lower():
                                self._log(f"[HIPS] 已终止广告进程: {name}", True)
                                try:
                                    proc.terminate()
                                except:
                                    pass
                                break
                    except:
                        pass
            except:
                pass
            time.sleep(5)


# ==================== 弹窗拦截（修复版 - 不拦截自己）====================
class PopupBlocker:
    def __init__(self, log_callback=None):
        self.running = False
        self.thread = None
        self.log_callback = log_callback
        self.blocked_count = 0
        
        # 自身窗口白名单（不拦截）
        self.self_window_titles = [
            "青柠杀毒 LS",
            "广告拦截设置",
            "隔离区管理",
            "扫描日志",
            "设置",
            "关于",
            "快速扫描",
            "自定义扫描"
        ]
        
        # 自身进程ID
        self.self_pid = SELF_INFO["pid"]
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        self._log("弹窗拦截已启动")
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _log(self, msg: str, is_error: bool = False):
        if self.log_callback:
            self.log_callback(msg, is_error)
    
    def _get_window_pid(self, hwnd):
        """获取窗口所属进程ID"""
        try:
            pid = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            return pid.value
        except:
            return 0
    
    def _is_self_window(self, title, hwnd):
        """检查是否为自己的窗口"""
        # 检查标题
        for self_title in self.self_window_titles:
            if self_title in title:
                return True
        
        # 检查进程ID
        window_pid = self._get_window_pid(hwnd)
        if window_pid == self.self_pid:
            return True
        
        return False
    
    def _monitor_loop(self):
        existing_windows = set()
        
        def enum_callback(hwnd, windows):
            if win32gui.IsWindowVisible(hwnd):
                title = win32gui.GetWindowText(hwnd)
                if title:
                    windows.append(hwnd)
            return True
        
        while self.running:
            try:
                current_windows = []
                win32gui.EnumWindows(enum_callback, current_windows)
                current_set = set(current_windows)
                
                new_windows = current_set - existing_windows
                for hwnd in new_windows:
                    title = win32gui.GetWindowText(hwnd)
                    
                    # 检查是否为自己的窗口，是则跳过
                    if self._is_self_window(title, hwnd):
                        continue
                    
                    if self._is_ad_window(hwnd):
                        try:
                            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                            self.blocked_count += 1
                            self._log(f"🚫 已拦截广告弹窗: {title[:30]}")
                        except:
                            pass
                
                existing_windows = current_set
                time.sleep(1)
            except:
                pass
    
    def _is_ad_window(self, hwnd):
        """判断是否为广告窗口"""
        try:
            title = win32gui.GetWindowText(hwnd).lower()
            if not title:
                return False
            
            # 检查关键词
            for keyword in AD_KEYWORDS:
                if keyword.lower() in title:
                    return True
            
            for ad_title in AD_TITLES:
                if ad_title.lower() in title:
                    return True
            
            # 检查窗口大小
            rect = win32gui.GetWindowRect(hwnd)
            width = rect[2] - rect[0]
            height = rect[3] - rect[1]
            
            if 150 <= width <= 600 and 100 <= height <= 500:
                ad_indicators = ["ad", "pop", "优惠", "抽奖", "红包", "免费", "中奖"]
                if any(ind in title for ind in ad_indicators):
                    return True
            
            if not title and 200 <= width <= 400 and 150 <= height <= 300:
                return True
                
        except:
            pass
        return False


# ==================== 隔离区 ====================
class QuarantineManager:
    def __init__(self, quarantine_path: Path):
        self.quarantine_path = quarantine_path
        self.quarantine_path.mkdir(parents=True, exist_ok=True)
        self.items = []
        self.load()
    
    def load(self):
        index_file = self.quarantine_path / "index.json"
        if index_file.exists():
            try:
                with open(index_file, 'r', encoding='utf-8') as f:
                    self.items = json.load(f)
            except:
                self.items = []
    
    def save(self):
        with open(self.quarantine_path / "index.json", 'w', encoding='utf-8') as f:
            json.dump(self.items, f, indent=2, ensure_ascii=False)
    
    def quarantine(self, file_path: str, virus_name: str) -> bool:
        # 不能隔离自己
        if file_path == SELF_INFO["path"]:
            return False
        
        try:
            if not os.path.exists(file_path):
                return False
            
            timestamp = int(time.time())
            original_name = Path(file_path).name
            quarantined_name = f"{timestamp}_{original_name}.q"
            quarantined_path = self.quarantine_path / quarantined_name
            
            shutil.move(file_path, quarantined_path)
            
            self.items.append({
                "original_path": file_path,
                "quarantine_path": str(quarantined_path),
                "virus_name": virus_name,
                "quarantine_time": datetime.now().isoformat()
            })
            self.save()
            return True
        except:
            return False
    
    def restore(self, item_index: int) -> bool:
        try:
            item = self.items[item_index]
            shutil.move(item['quarantine_path'], item['original_path'])
            self.items.pop(item_index)
            self.save()
            return True
        except:
            return False
    
    def delete_permanent(self, item_index: int) -> bool:
        try:
            os.remove(self.items[item_index]['quarantine_path'])
            self.items.pop(item_index)
            self.save()
            return True
        except:
            return False
    
    def get_list(self) -> List[dict]:
        return self.items


# ==================== 实时监控 ====================
class RealTimeMonitor:
    def __init__(self, scan_engine: ScanEngine, quarantine_mgr, log_callback=None):
        self.scan_engine = scan_engine
        self.quarantine_mgr = quarantine_mgr
        self.log_callback = log_callback
        self.running = False
        self.thread = None
        
        self.monitored_paths = [
            os.environ.get('TEMP', 'C:\\Windows\\Temp'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
        ]
        self.monitored_paths = [p for p in self.monitored_paths if os.path.exists(p)]
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        self._log("实时监控已启动")
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _log(self, msg: str, is_error: bool = False):
        if self.log_callback:
            self.log_callback(msg, is_error)
    
    def _monitor_loop(self):
        file_cache = {}
        
        while self.running:
            try:
                for monitor_path in self.monitored_paths:
                    if not os.path.exists(monitor_path):
                        continue
                    
                    try:
                        for file in os.listdir(monitor_path):
                            file_path = os.path.join(monitor_path, file)
                            if not os.path.isfile(file_path):
                                continue
                            
                            ext = Path(file_path).suffix.lower()
                            if ext not in ['.exe', '.scr', '.bat']:
                                continue
                            
                            try:
                                mtime = os.path.getmtime(file_path)
                                if file_path in file_cache:
                                    if file_cache[file_path] != mtime:
                                        pass
                                else:
                                    self._on_file_created(file_path)
                                file_cache[file_path] = mtime
                            except:
                                pass
                    except:
                        pass
                
                if len(file_cache) > 500:
                    file_cache.clear()
                
                time.sleep(3)
            except:
                time.sleep(10)
    
    def _on_file_created(self, file_path: str):
        # 跳过自身
        if file_path == SELF_INFO["path"]:
            return
        
        virus_name, level = self.scan_engine.scan_file(file_path)
        if virus_name and level >= 5:
            self._log(f"[监控] 检测到威胁: {virus_name}", True)
            self.quarantine_mgr.quarantine(file_path, virus_name)


# ==================== 主界面 ====================
class LimeAntivirusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("青柠杀毒 LS")
        self.root.geometry("800x650")
        self.root.configure(bg='#c8f0d2')
        
        # 设置图标
        try:
            if getattr(sys, 'frozen', False):
                icon_path = os.path.join(sys._MEIPASS, 'icon.ico')
            else:
                icon_path = 'icon.ico'
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except:
            pass
        
        # 数据目录
        self.data_path = Path(os.environ.get('APPDATA', '.')) / "LimeAntivirus"
        self.data_path.mkdir(parents=True, exist_ok=True)
        
        # 初始化组件
        self.virus_db = VirusDatabase(self.data_path)
        self.scan_engine = ScanEngine(self.virus_db)
        self.quarantine_mgr = QuarantineManager(self.data_path / "quarantine")
        
        self.real_time_monitor = None
        self.hips_monitor = None
        self.popup_blocker = None
        self.scan_thread = None
        
        self._create_widgets()
        self._init_monitors()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # 启动后显示自身信息
        self.log_message(f"自身PID: {SELF_INFO['pid']}, 名称: {SELF_INFO['name']}")
        self.log_message("已添加到白名单，不会拦截自己")
    
    def _init_monitors(self):
        self.real_time_monitor = RealTimeMonitor(self.scan_engine, self.quarantine_mgr, self.log_message)
        self.hips_monitor = HIPSMonitor(self.log_message)
        self.popup_blocker = PopupBlocker(self.log_message)
        
        self.real_time_monitor.start()
        self.hips_monitor.start()
        self.popup_blocker.start()
    
    def _create_widgets(self):
        # 标题
        title_frame = tk.Frame(self.root, bg='#c8f0d2')
        title_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(title_frame, text="🍋 青柠杀毒 LS", font=("微软雅黑", 22, "bold"),
                 fg='#2d5a2d', bg='#c8f0d2').pack(side='left')
        tk.Label(title_frame, text="● 保护中", font=("微软雅黑", 10),
                 fg='green', bg='#c8f0d2').pack(side='right', padx=10)
        
        # 第一行按钮
        btn_frame = tk.Frame(self.root, bg='#c8f0d2')
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        self.scan_btn = tk.Button(btn_frame, text="🔍 快速扫描", font=("微软雅黑", 11),
                                   bg='#4CAF50', fg='white', padx=15, pady=5,
                                   command=self.start_quick_scan)
        self.scan_btn.pack(side='left', padx=5)
        
        self.custom_btn = tk.Button(btn_frame, text="📁 自定义扫描", font=("微软雅黑", 11),
                                     bg='#2196F3', fg='white', padx=15, pady=5,
                                     command=self.start_custom_scan)
        self.custom_btn.pack(side='left', padx=5)
        
        self.stop_btn = tk.Button(btn_frame, text="⏹️ 停止扫描", font=("微软雅黑", 11),
                                   bg='#f44336', fg='white', padx=15, pady=5,
                                   command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        self.quarantine_btn = tk.Button(btn_frame, text="📦 隔离区", font=("微软雅黑", 11),
                                         bg='#FF9800', fg='white', padx=15, pady=5,
                                         command=self.show_quarantine)
        self.quarantine_btn.pack(side='left', padx=5)
        
        # 第二行按钮
        btn_frame2 = tk.Frame(self.root, bg='#c8f0d2')
        btn_frame2.pack(fill='x', padx=10, pady=5)
        
        self.adblock_btn = tk.Button(btn_frame2, text="🛡️ 广告拦截", font=("微软雅黑", 11),
                                      bg='#9C27B0', fg='white', padx=15, pady=5,
                                      command=self.show_adblock_settings)
        self.adblock_btn.pack(side='left', padx=5)
        
        self.adblock_status_label = tk.Label(btn_frame2, text="", font=("微软雅黑", 9),
                                              bg='#c8f0d2', fg='green')
        self.adblock_status_label.pack(side='left', padx=10)
        
        # 进度条
        progress_frame = tk.Frame(self.root, bg='#c8f0d2')
        progress_frame.pack(fill='x', padx=10, pady=10)
        
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', padx=5)
        
        self.progress_label = tk.Label(progress_frame, text="就绪", bg='#c8f0d2', fg='#555')
        self.progress_label.pack(pady=5)
        
        # 日志
        log_frame = tk.LabelFrame(self.root, text="扫描日志", font=("微软雅黑", 10), bg='#c8f0d2')
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=18, font=("Consolas", 9),
                                                   bg='#e8f5e9', fg='#1b5e20')
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # 状态栏
        status_frame = tk.Frame(self.root, bg='#c8f0d2', relief='sunken', bd=1)
        status_frame.pack(fill='x', side='bottom')
        
        self.status_var = tk.StringVar(value="就绪 | 实时监控已启用 | HIPS已启用 | 弹窗拦截已启用")
        tk.Label(status_frame, textvariable=self.status_var, bg='#c8f0d2', fg='#555').pack(padx=10, pady=5)
        
        # 配置日志颜色
        self.log_text.tag_config("error", foreground="red")
        self.log_text.tag_config("virus", foreground="darkorange")
        self.log_text.tag_config("hips", foreground="purple")
        self.log_text.tag_config("info", foreground="green")
        
        self.log_message("青柠杀毒 LS 已启动")
        
        self.update_adblock_status()
    
    def update_adblock_status(self):
        try:
            enabled = HostsManager.get_status()
            if enabled:
                self.adblock_status_label.config(text="✓ Hosts广告拦截已启用", fg="green")
            else:
                self.adblock_status_label.config(text="✗ Hosts广告拦截未启用", fg="red")
        except:
            self.adblock_status_label.config(text="✗ 无法检测状态", fg="red")
    
    def log_message(self, msg: str, is_error: bool = False):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if is_error:
            tag = "error"
            prefix = "❌"
        elif "威胁" in msg or "病毒" in msg:
            tag = "virus"
            prefix = "⚠️"
        elif "HIPS" in msg:
            tag = "hips"
            prefix = "🛡️"
        elif "拦截" in msg:
            tag = "info"
            prefix = "🚫"
        else:
            tag = "info"
            prefix = "ℹ️"
        
        line = f"[{timestamp}] {prefix} {msg}\n"
        
        def insert():
            self.log_text.insert(tk.END, line, tag)
            self.log_text.see(tk.END)
            if int(self.log_text.index('end-1c').split('.')[0]) > 1000:
                self.log_text.delete(1.0, 500.0)
        
        self.log_text.after(0, insert)
    
    def update_progress(self, current: int, total: int, virus_name: str = ""):
        if total > 0:
            percent = int(current / total * 100)
            self.progress_var.set(percent)
            self.progress_label.config(text=f"已扫描: {current}/{total} ({percent}%)")
            if virus_name:
                self.log_message(f"发现威胁: {virus_name}", True)
    
    def start_quick_scan(self):
        scan_path = os.environ.get('SYSTEMDRIVE', 'C:\\')
        self._start_scan(scan_path)
    
    def start_custom_scan(self):
        path = filedialog.askdirectory(title="选择要扫描的文件夹")
        if path:
            self._start_scan(path)
    
    def _start_scan(self, path: str):
        if self.scan_thread and self.scan_thread.is_alive():
            self.log_message("扫描正在进行中...")
            return
        
        self.scan_engine.stop_scan = False
        self.scan_engine.set_callback(self.update_progress)
        
        self.scan_btn.config(state='disabled')
        self.custom_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress_var.set(0)
        
        self.log_message(f"开始扫描: {path}")
        
        def scan_task():
            result = self.scan_engine.scan_directory(path)
            self.root.after(0, self._on_scan_complete, result)
        
        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()
    
    def stop_scan(self):
        self.scan_engine.stop()
        self.log_message("正在停止扫描...")
        self.stop_btn.config(state='disabled')
    
    def _on_scan_complete(self, result: ScanResult):
        self.scan_btn.config(state='normal')
        self.custom_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
        self.log_message("=" * 50)
        self.log_message(f"扫描完成！总文件: {result.total_files}, 威胁: {result.infected_files}")
        
        for virus in result.viruses:
            self.log_message(f"  - {virus.name}: {virus.file_path}", True)
            if virus.threat_level >= 5:
                if self.quarantine_mgr.quarantine(virus.file_path, virus.name):
                    self.log_message(f"    已自动隔离", False)
        
        self.log_message("=" * 50)
        self.status_var.set(f"扫描完成 | 发现 {result.infected_files} 个威胁")
        self.progress_label.config(text="扫描完成")
    
    def show_quarantine(self):
        win = tk.Toplevel(self.root)
        win.title("隔离区管理")
        win.geometry("650x400")
        win.configure(bg='#c8f0d2')
        
        columns = ("病毒名称", "原始路径", "隔离时间")
        tree = ttk.Treeview(win, columns=columns, show="headings", height=15)
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=250 if col == "原始路径" else 150)
        tree.pack(fill='both', expand=True, padx=10, pady=10)
        
        btn_frame = tk.Frame(win, bg='#c8f0d2')
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        def refresh():
            for item in tree.get_children():
                tree.delete(item)
            for i, item in enumerate(self.quarantine_mgr.get_list()):
                tree.insert("", "end", iid=str(i), values=(
                    item.get('virus_name', '未知'),
                    item.get('original_path', '')[:60],
                    item.get('quarantine_time', '')[:19]
                ))
        
        def restore():
            sel = tree.selection()
            if sel and self.quarantine_mgr.restore(int(sel[0])):
                refresh()
                self.log_message("已恢复文件")
        
        def delete():
            sel = tree.selection()
            if sel and messagebox.askyesno("确认", "永久删除？不可恢复！"):
                if self.quarantine_mgr.delete_permanent(int(sel[0])):
                    refresh()
                    self.log_message("已永久删除")
        
        tk.Button(btn_frame, text="恢复文件", bg='#4CAF50', fg='white', command=restore).pack(side='left', padx=5)
        tk.Button(btn_frame, text="永久删除", bg='#f44336', fg='white', command=delete).pack(side='left', padx=5)
        tk.Button(btn_frame, text="刷新", bg='#2196F3', fg='white', command=refresh).pack(side='right', padx=5)
        
        refresh()
    
    def show_adblock_settings(self):
        """显示广告拦截设置窗口"""
        win = tk.Toplevel(self.root)
        win.title("广告拦截设置")
        win.geometry("550x500")
        win.configure(bg='#c8f0d2')
        
        hosts_enabled = HostsManager.get_status()
        
        status_frame = tk.Frame(win, bg='#c8f0d2', relief='ridge', bd=1)
        status_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(status_frame, text="🛡️ 广告拦截设置", font=("微软雅黑", 14, "bold"),
                 bg='#c8f0d2', fg='#333').pack(pady=10)
        
        hosts_frame = tk.Frame(status_frame, bg='#c8f0d2')
        hosts_frame.pack(fill='x', padx=10, pady=10)
        
        hosts_status_text = "✓ 已启用" if hosts_enabled else "✗ 未启用"
        hosts_color = "green" if hosts_enabled else "red"
        hosts_status_label = tk.Label(hosts_frame, text=hosts_status_text, 
                                       fg=hosts_color, bg='#c8f0d2', font=("微软雅黑", 11))
        hosts_status_label.pack(side='left', padx=5)
        
        def toggle_hosts():
            nonlocal hosts_enabled, hosts_status_label
            if hosts_enabled:
                success, msg = HostsManager.disable_ad_block()
                if success:
                    hosts_enabled = False
                    self.log_message(f"已禁用 hosts 广告拦截")
                else:
                    messagebox.showerror("错误", msg)
            else:
                if not HostsManager.is_admin():
                    result = messagebox.askyesno("权限请求", 
                        "启用 hosts 广告拦截需要管理员权限。\n是否以管理员身份重新运行程序？")
                    if result:
                        ctypes.windll.shell32.ShellExecuteW(
                            None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                        self.root.quit()
                    return
                success, msg = HostsManager.enable_ad_block()
                if success:
                    hosts_enabled = True
                    self.log_message(f"已启用 hosts 广告拦截")
                    self.update_adblock_status()
                else:
                    messagebox.showerror("错误", msg)
            
            hosts_btn.config(text="禁用" if hosts_enabled else "启用",
                           bg='#f44336' if hosts_enabled else '#4CAF50')
            hosts_status_label.config(text="✓ 已启用" if hosts_enabled else "✗ 未启用",
                                     fg="green" if hosts_enabled else "red")
        
        hosts_btn = tk.Button(hosts_frame, text="禁用" if hosts_enabled else "启用",
                              bg='#f44336' if hosts_enabled else '#4CAF50',
                              fg='white', padx=15, pady=3, command=toggle_hosts)
        hosts_btn.pack(side='right')
        
        info_frame = tk.Frame(win, bg='#c8f0d2')
        info_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(info_frame, text="📋 拦截说明:", font=("微软雅黑", 10, "bold"),
                 bg='#c8f0d2', fg='#333').pack(anchor='w')
        tk.Label(info_frame, text="  • 将广告域名指向本地，从源头屏蔽广告", 
                 bg='#c8f0d2', fg='#555').pack(anchor='w')
        tk.Label(info_frame, text=f"  • 当前拦截规则数: {len(AD_DOMAINS)} 条", 
                 bg='#c8f0d2', fg='#555').pack(anchor='w')
        
        tip_frame = tk.Frame(win, bg='#e8f5e9', relief='sunken', bd=1)
        tip_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(tip_frame, text="💡 提示:", font=("微软雅黑", 9, "bold"),
                 bg='#e8f5e9', fg='orange').pack(padx=10, pady=5, anchor='w')
        tk.Label(tip_frame, text="• 启用 hosts 拦截需要管理员权限", 
                 bg='#e8f5e9', fg='#555', font=("微软雅黑", 8)).pack(padx=10, anchor='w')
        tk.Label(tip_frame, text="• 启用后请重启浏览器使规则生效", 
                 bg='#e8f5e9', fg='#555', font=("微软雅黑", 8)).pack(padx=10, anchor='w')
        tk.Label(tip_frame, text="• 本程序已加入白名单，不会被拦截", 
                 bg='#e8f5e9', fg='green', font=("微软雅黑", 8)).pack(padx=10, anchor='w')
    
    def on_closing(self):
        self.log_message("正在关闭程序...")
        if self.real_time_monitor:
            self.real_time_monitor.stop()
        if self.hips_monitor:
            self.hips_monitor.stop()
        if self.popup_blocker:
            self.popup_blocker.stop()
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()


def main():
    # 隐藏控制台窗口
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass
    
    try:
        app = LimeAntivirusGUI()
        app.run()
    except Exception as e:
        messagebox.showerror("错误", f"启动失败: {e}")


if __name__ == "__main__":
    main()