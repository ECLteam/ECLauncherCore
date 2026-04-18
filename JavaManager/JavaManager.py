"""
Java 管理器 - 跨平台查找、管理 Java 运行时
支持扫描系统 Java、缓存、添加/移除、选择适合 Minecraft 的 Java 版本。
"""

import os
import re
import json
import shutil
import subprocess
import platform as sys_platform
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple, Callable
from dataclasses import dataclass
from enum import Enum
import hashlib

# ========== 平台相关基础类 ==========

class OperatingSystem(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    FREEBSD = "freebsd"
    UNKNOWN = "unknown"

    @classmethod
    def parse_os_name(cls, name: str) -> "OperatingSystem":
        name_lower = name.lower()
        if "windows" in name_lower:
            return cls.WINDOWS
        if "linux" in name_lower:
            return cls.LINUX
        if "mac" in name_lower or "darwin" in name_lower:
            return cls.MACOS
        if "freebsd" in name_lower:
            return cls.FREEBSD
        return cls.UNKNOWN

    @classmethod
    def current(cls) -> "OperatingSystem":
        system = sys_platform.system()
        if system == "Windows":
            return cls.WINDOWS
        if system == "Linux":
            return cls.LINUX
        if system == "Darwin":
            return cls.MACOS
        if system == "FreeBSD":
            return cls.FREEBSD
        return cls.UNKNOWN

    def get_java_executable(self) -> str:
        return "java.exe" if self == self.WINDOWS else "java"


class Architecture(Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    AARCH64 = "aarch64"
    UNKNOWN = "unknown"

    @classmethod
    def parse_arch_name(cls, name: str) -> "Architecture":
        name_lower = name.lower()
        if name_lower in ("x86", "i386", "i486", "i586", "i686"):
            return cls.X86
        if name_lower in ("amd64", "x86_64", "x64"):
            return cls.X86_64
        if name_lower in ("arm", "arm32"):
            return cls.ARM
        if name_lower in ("aarch64", "arm64"):
            return cls.AARCH64
        return cls.UNKNOWN

    @classmethod
    def current(cls) -> "Architecture":
        return cls.parse_arch_name(sys_platform.machine())

    def is_x86(self) -> bool:
        return self in (self.X86, self.X86_64)


@dataclass
class Platform:
    os: OperatingSystem
    arch: Architecture

    @classmethod
    def current(cls) -> "Platform":
        return cls(OperatingSystem.current(), Architecture.current())

    def __str__(self) -> str:
        return f"{self.os.value}-{self.arch.value}"


# ========== 版本比较工具 ==========

class VersionNumber:
    """版本号比较（基于数字元组）"""
    def __init__(self, version_str: str):
        self.raw = version_str
        self._parts = []
        for part in re.split(r"[._-]", version_str):
            if part.isdigit():
                self._parts.append(int(part))
            else:
                # 遇到非数字停止（如 "ea"）
                break

    def __lt__(self, other: "VersionNumber") -> bool:
        return self._parts < other._parts

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VersionNumber):
            return False
        return self._parts == other._parts

    def compare_to(self, other: "VersionNumber") -> int:
        if self._parts < other._parts:
            return -1
        if self._parts > other._parts:
            return 1
        return 0


def parse_java_version(version_str: str) -> int:
    """解析 Java 主版本号，例如 1.8.0_292 -> 8, 17.0.1 -> 17"""
    start = 2 if version_str.startswith("1.") else 0
    end = start
    while end < len(version_str) and version_str[end].isdigit():
        end += 1
    if end > start:
        try:
            return int(version_str[start:end])
        except ValueError:
            pass
    return -1


def normalize_vendor(vendor: Optional[str]) -> Optional[str]:
    if not vendor:
        return None
    mapping = {
        "N/A": None,
        "Oracle Corporation": "Oracle",
        "Azul Systems, Inc.": "Azul",
        "IBM Corporation": "IBM",
        "International Business Machines Corporation": "IBM",
        "Eclipse OpenJ9": "IBM",
        "Eclipse Adoptium": "Adoptium",
        "Amazon.com Inc.": "Amazon",
    }
    return mapping.get(vendor, vendor)


# ========== JavaInfo ==========

@dataclass
class JavaInfo:
    platform: Platform
    version: str
    vendor: Optional[str] = None

    def __post_init__(self):
        self.parsed_version = parse_java_version(self.version)
        self.version_number = VersionNumber(self.version)

    @classmethod
    def from_executable(cls, executable: Path, log_callback: Optional[Callable[[str], None]] = None) -> "JavaInfo":
        """
        通过执行 `java -version` 或读取 release 文件获取信息。
        优先读取 release 文件（更快），失败则执行命令。
        """
        java_home = executable.parent.parent  # bin 的父目录
        release_file = java_home / "release"
        if release_file.is_file():
            try:
                return cls._from_release_file(release_file)
            except Exception as e:
                if log_callback:
                    log_callback(f"读取 release 文件失败: {e}，回退到执行 java -version")

        # 回退：执行 java -version
        return cls._from_java_command(executable)

    @classmethod
    def _from_release_file(cls, release_file: Path) -> "JavaInfo":
        props = {}
        with release_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    props[key.strip()] = value.strip().strip('"')
        os_name = props.get("OS_NAME", "")
        os_arch = props.get("OS_ARCH", "")
        vendor = props.get("IMPLEMENTOR")
        java_version = props.get("JAVA_VERSION")
        if not java_version:
            raise ValueError("release 文件中缺少 JAVA_VERSION")
        operating_system = OperatingSystem.parse_os_name(os_name)
        architecture = Architecture.parse_arch_name(os_arch)
        if operating_system == OperatingSystem.UNKNOWN:
            raise ValueError(f"未知操作系统: {os_name}")
        if architecture == Architecture.UNKNOWN:
            raise ValueError(f"未知架构: {os_arch}")
        platform_obj = Platform(operating_system, architecture)
        return cls(platform_obj, java_version, normalize_vendor(vendor))

    @classmethod
    def _from_java_command(cls, java_exe: Path) -> "JavaInfo":
        try:
            result = subprocess.run(
                [str(java_exe), "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stderr.strip()
        except Exception as e:
            raise RuntimeError(f"执行 java -version 失败: {e}")

        # 解析版本
        version_match = re.search(r'version "([^"]+)"', output)
        if not version_match:
            raise ValueError("无法从输出中解析 Java 版本")
        version = version_match.group(1)

        # 解析供应商
        vendor = None
        if "OpenJDK" in output:
            vendor = "OpenJDK"
        elif "Oracle" in output:
            vendor = "Oracle"
        elif "Azul" in output:
            vendor = "Azul"
        elif "IBM" in output:
            vendor = "IBM"
        elif "Adoptium" in output:
            vendor = "Adoptium"
        elif "Amazon" in output:
            vendor = "Amazon"

        platform_obj = Platform.current()  # 执行命令的平台即为当前平台
        return cls(platform_obj, version, vendor)

    @classmethod
    def current_environment(cls, java_home: Optional[Path] = None) -> Optional["JavaInfo"]:
        """获取当前环境的 Java 信息（通过 JAVA_HOME 或 PATH 中的 java）"""
        if java_home is None:
            java_home_env = os.environ.get("JAVA_HOME")
            if java_home_env:
                java_home = Path(java_home_env)
        if java_home:
            release = java_home / "release"
            if release.is_file():
                try:
                    return cls._from_release_file(release)
                except Exception:
                    pass
        # 从 PATH 查找 java
        java_exe = shutil.which(OperatingSystem.current().get_java_executable())
        if java_exe:
            try:
                return cls.from_executable(Path(java_exe))
            except Exception:
                pass
        return None


# ========== JavaRuntime ==========

@dataclass(order=True)
class JavaRuntime:
    binary: Path
    info: JavaInfo
    is_managed: bool = False  # 是否由启动器管理（可卸载）

    def __post_init__(self):
        self._cached_key = None

    @property
    def platform(self) -> Platform:
        return self.info.platform

    @property
    def version(self) -> str:
        return self.info.version

    @property
    def version_number(self) -> VersionNumber:
        return self.info.version_number

    @property
    def parsed_version(self) -> int:
        return self.info.parsed_version

    @property
    def vendor(self) -> Optional[str]:
        return self.info.vendor

    @property
    def architecture(self) -> Architecture:
        return self.info.platform.arch

    def is_jdk(self) -> bool:
        """简单判断：如果存在 javac 则为 JDK"""
        javac_path = self.binary.parent / ("javac.exe" if self.platform.os == OperatingSystem.WINDOWS else "javac")
        return javac_path.is_file()

    @classmethod
    def current_environment(cls) -> Optional["JavaRuntime"]:
        """获取当前运行环境的 Java 运行时（通过 JAVA_HOME 或 PATH）"""
        info = JavaInfo.current_environment()
        if info is None:
            return None
        # 获取可执行文件路径
        java_exe_name = info.platform.os.get_java_executable()
        java_exe = shutil.which(java_exe_name)
        if java_exe:
            binary = Path(java_exe).resolve()
            return cls(binary, info, is_managed=False)
        return None


# ========== JavaRepository（管理安装目录） ==========

class JavaRepository:
    """管理 Java 安装的目录结构，类似 HMCLJavaRepository"""

    MOJANG_JAVA_PREFIX = "mojang-"

    def __init__(self, root: Path, log_callback: Optional[Callable[[str], None]] = None):
        self.root = root
        self._log = log_callback or print

    def get_platform_root(self, platform: Platform) -> Path:
        return self.root / str(platform)

    def get_java_dir(self, platform: Platform, name: str) -> Path:
        return self.get_platform_root(platform) / name

    def get_manifest_file(self, platform: Platform, name: str) -> Path:
        return self.get_platform_root(platform) / f"{name}.json"

    def is_installed(self, platform: Platform, name: str) -> bool:
        return self.get_manifest_file(platform, name).is_file()

    def get_java_executable(self, platform: Platform, name: str) -> Optional[Path]:
        java_dir = self.get_java_dir(platform, name)
        executable = java_dir / "bin" / platform.os.get_java_executable()
        if executable.is_file():
            try:
                return executable.resolve()
            except Exception:
                pass
        if platform.os == OperatingSystem.MACOS:
            mac_exec = java_dir / "jre.bundle/Contents/Home/bin/java"
            if mac_exec.is_file():
                try:
                    return mac_exec.resolve()
                except Exception:
                    pass
        return None

    def get_all_java(self, platform: Platform) -> List[Path]:
        platform_root = self.get_platform_root(platform)
        if not platform_root.is_dir():
            return []
        result = []
        for item in platform_root.iterdir():
            if item.is_dir():
                # 检查对应的 manifest 文件
                manifest = platform_root / f"{item.name}.json"
                if manifest.is_file():
                    executable = self.get_java_executable(platform, item.name)
                    if executable:
                        result.append(executable)
        return result

    def save_manifest(self, platform: Platform, name: str, manifest: dict):
        manifest_file = self.get_manifest_file(platform, name)
        manifest_file.parent.mkdir(parents=True, exist_ok=True)
        with manifest_file.open("w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

    def remove_java(self, platform: Platform, name: str):
        manifest = self.get_manifest_file(platform, name)
        if manifest.exists():
            manifest.unlink()
        java_dir = self.get_java_dir(platform, name)
        if java_dir.is_dir():
            shutil.rmtree(java_dir, ignore_errors=True)


# ========== JavaManager 核心 ==========

class JavaManager:
    """Java 运行时管理器，负责扫描、缓存、选择等"""

    # 已知的 Windows 供应商目录（用于扫描 Program Files）
    KNOWN_VENDOR_DIRECTORIES = [
        "Java", "BellSoft", "AdoptOpenJDK", "Zulu", "Microsoft", "Eclipse Foundation", "Semeru"
    ]

    def __init__(self, global_root: Optional[Path] = None, log_callback: Optional[Callable[[str], None]] = None):
        """
        :param global_root: 存储托管 Java 的根目录，默认为当前目录下的 java 文件夹
        :param log_callback: 日志回调
        """
        if global_root is None:
            global_root = Path.cwd() / "java"
        self.repository = JavaRepository(global_root, log_callback)
        self._log = log_callback or print
        self._cache_file = global_root / "java_cache.json"
        self._java_runtimes: Dict[Path, JavaRuntime] = {}
        self._failed_paths: Set[Path] = set()
        self._caches: Dict[Path, Tuple[str, JavaInfo]] = {}  # real_path -> (cache_key, JavaInfo)
        self._need_save_cache = False

        # 用户手动添加的 Java 路径（从配置文件加载）
        self._user_java_paths: Set[str] = set()
        # 禁用的 Java 路径
        self._disabled_java_paths: Set[str] = set()

    # ========== 缓存管理 ==========

    def _create_cache_key(self, real_path: Path) -> Optional[str]:
        """为 Java 可执行文件生成缓存键，基于文件大小、修改时间和 release 文件哈希"""
        try:
            bin_dir = real_path.parent
            if bin_dir.name != "bin":
                return None
            java_home = bin_dir.parent
            lib_dir = java_home / "lib"
            if not lib_dir.is_dir():
                return None

            stat = real_path.stat()
            parts = [f"sz:{stat.st_size}", f"lm:{int(stat.st_mtime * 1000)}"]

            release_file = java_home / "release"
            if release_file.is_file():
                sha1 = hashlib.sha1()
                sha1.update(release_file.read_bytes())
                parts.append(sha1.hexdigest())
            else:
                rt_jar = lib_dir / "rt.jar"
                if not rt_jar.is_file():
                    rt_jar = java_home / "jre/lib/rt.jar"
                if rt_jar.is_file():
                    rstat = rt_jar.stat()
                    parts.append(f"rsz:{rstat.st_size}")
                    parts.append(f"rlm:{int(rstat.st_mtime * 1000)}")
                else:
                    return None
            return ",".join(parts)
        except Exception as e:
            self._log(f"生成缓存键失败 {real_path}: {e}")
            return None

    def _load_cache(self):
        """从缓存文件加载缓存的 JavaInfo"""
        if not self._cache_file.is_file():
            return
        try:
            with self._cache_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            version = data.get("version", "0.0")
            # 简单版本检查
            if version.split(".")[0] != "1":
                self._log("缓存文件版本不兼容，忽略")
                return
            for entry in data.get("caches", []):
                try:
                    path = Path(entry["path"])
                    key = entry["key"]
                    os_name = entry["os.name"]
                    os_arch = entry["os.arch"]
                    java_version = entry["java.version"]
                    vendor = entry.get("java.vendor")
                    platform = Platform(OperatingSystem.parse_os_name(os_name), Architecture.parse_arch_name(os_arch))
                    info = JavaInfo(platform, java_version, vendor)
                    self._caches[path] = (key, info)
                except Exception as e:
                    self._log(f"缓存条目无效: {entry}, 错误: {e}")
                    self._need_save_cache = True
        except Exception as e:
            self._log(f"加载缓存文件失败: {e}")
            self._need_save_cache = True

    def _save_cache(self):
        if not self._need_save_cache:
            return
        self._need_save_cache = False
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "version": "1.0",
                "caches": [
                    {
                        "path": str(path),
                        "key": key,
                        "os.name": info.platform.os.value,
                        "os.arch": info.platform.arch.value,
                        "java.version": info.version,
                        "java.vendor": info.vendor
                    }
                    for path, (key, info) in self._caches.items()
                ]
            }
            with self._cache_file.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self._log(f"保存缓存失败: {e}")

    # ========== Java 添加/移除 ==========

    def add_java(self, runtime: JavaRuntime):
        """添加一个 Java 运行时到内存（用户手动添加）"""
        real_path = runtime.binary.resolve()
        if real_path not in self._java_runtimes:
            self._java_runtimes[real_path] = runtime
            self._need_save_cache = True

    def remove_java(self, binary: Path):
        real_path = binary.resolve()
        self._java_runtimes.pop(real_path, None)
        self._caches.pop(real_path, None)
        self._failed_paths.discard(real_path)
        self._need_save_cache = True

    def disable_java(self, binary: Path):
        self._disabled_java_paths.add(str(binary.resolve()))

    def enable_java(self, binary: Path):
        self._disabled_java_paths.discard(str(binary.resolve()))

    def is_disabled(self, binary: Path) -> bool:
        return str(binary.resolve()) in self._disabled_java_paths

    # ========== 扫描单个 Java ==========

    def _try_add_java_executable(self, executable: Path, is_managed: bool = False):
        """尝试添加一个 Java 可执行文件，如果有效则加入 _java_runtimes"""
        try:
            real_path = executable.resolve()
        except Exception:
            return

        if real_path in self._java_runtimes or real_path in self._failed_paths:
            return
        if self.is_disabled(real_path):
            return

        # 尝试从缓存获取 JavaInfo
        cache_key = self._create_cache_key(real_path)
        info = None
        if cache_key:
            cached = self._caches.get(real_path)
            if cached and cached[0] == cache_key:
                info = cached[1]

        if info is None:
            try:
                info = JavaInfo.from_executable(real_path, self._log)
            except Exception as e:
                self._log(f"无法识别 Java 可执行文件 {real_path}: {e}")
                self._failed_paths.add(real_path)
                return
            if cache_key:
                self._caches[real_path] = (cache_key, info)
                self._need_save_cache = True

        runtime = JavaRuntime(real_path, info, is_managed)
        self._java_runtimes[real_path] = runtime

    def _try_add_java_home(self, java_home: Path, is_managed: bool = False):
        """尝试通过 JAVA_HOME 路径添加"""
        executable = java_home / "bin" / OperatingSystem.current().get_java_executable()
        if executable.is_file():
            self._try_add_java_executable(executable, is_managed)

    # ========== 平台特定扫描 ==========

    def _scan_windows_registry(self):
        """扫描 Windows 注册表中的 Java"""
        try:
            import winreg
        except ImportError:
            return

        def query_registry(hive, subkey):
            try:
                key = winreg.OpenKey(hive, subkey)
                # 尝试 CurrentVersion
                try:
                    current_version = winreg.QueryValueEx(key, "CurrentVersion")[0]
                    version_key = winreg.OpenKey(key, current_version)
                    java_home = winreg.QueryValueEx(version_key, "JavaHome")[0]
                    self._try_add_java_home(Path(java_home))
                except OSError:
                    pass
                # 遍历子键
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        version_key = winreg.OpenKey(key, subkey_name)
                        java_home = winreg.QueryValueEx(version_key, "JavaHome")[0]
                        self._try_add_java_home(Path(java_home))
                        i += 1
                    except OSError:
                        break
            except OSError:
                pass

        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\JavaSoft\Java Runtime Environment"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\JavaSoft\Java Development Kit"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\JavaSoft\JRE"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\JavaSoft\JDK"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\JavaSoft\JDK"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\JavaSoft\JRE"),
        ]
        for hive, subkey in registry_paths:
            query_registry(hive, subkey)

    def _scan_windows_program_files(self):
        """扫描 Windows Program Files 下的已知供应商目录"""
        program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
        for base in (program_files, program_files_x86):
            base_path = Path(base)
            if not base_path.is_dir():
                continue
            for vendor in self.KNOWN_VENDOR_DIRECTORIES:
                vendor_dir = base_path / vendor
                if vendor_dir.is_dir():
                    for item in vendor_dir.iterdir():
                        self._try_add_java_home(item)

    def _scan_linux_common_dirs(self):
        """扫描 Linux 常见 Java 安装目录"""
        common_dirs = [
            "/usr/java",
            "/usr/lib/jvm",
            "/usr/lib32/jvm",
            "/usr/lib64/jvm",
            Path.home() / ".sdkman/candidates/java",
            Path.home() / ".jdks",
        ]
        for d in common_dirs:
            path = Path(d)
            if path.is_dir():
                for sub in path.iterdir():
                    self._try_add_java_home(sub)

    def _scan_macos_java_virtual_machines(self):
        """扫描 macOS 的 JavaVirtualMachines"""
        for base in ("/Library/Java/JavaVirtualMachines", Path.home() / "Library/Java/JavaVirtualMachines"):
            base_path = Path(base)
            if base_path.is_dir():
                for jdk in base_path.iterdir():
                    home = jdk / "Contents/Home"
                    if home.is_dir():
                        self._try_add_java_home(home)
        # 特殊位置
        special_paths = [
            "/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Home/bin/java",
            "/Applications/Xcode.app/Contents/Applications/Application Loader.app/Contents/MacOS/itms/java/bin/java",
            "/opt/homebrew/opt/java/bin/java",
        ]
        for sp in special_paths:
            self._try_add_java_executable(Path(sp))
        # Homebrew cellar
        homebrew_cellar = Path("/opt/homebrew/Cellar/openjdk")
        if homebrew_cellar.is_dir():
            for sub in homebrew_cellar.iterdir():
                self._try_add_java_home(sub)
        # Homebrew 版本匹配
        homebrew_base = Path("/opt/homebrew/Cellar")
        if homebrew_base.is_dir():
            for pattern in homebrew_base.glob("openjdk@*"):
                self._try_add_java_home(pattern)

    def _scan_macos_java_home_command(self):
        """使用 /usr/libexec/java_home 命令获取 Java 列表"""
        try:
            output = subprocess.check_output(
                ["/usr/libexec/java_home", "-V"],
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5
            )
            for line in output.splitlines():
                for token in line.split():
                    if token.startswith("/"):
                        candidate = Path(token) / "bin/java"
                        if candidate.is_file():
                            self._try_add_java_executable(candidate)
                        break
        except Exception:
            pass

    def _scan_minecraft_bundled_runtimes(self):
        """扫描 Minecraft 自带运行时"""
        os_type = OperatingSystem.current()
        if os_type == OperatingSystem.WINDOWS:
            localappdata = os.environ.get("localappdata", "")
            if localappdata:
                runtime_path = Path(localappdata) / "Packages/Microsoft.4297127D64EC6_8wekyb3d8bbwe/LocalCache/Local/runtime"
                self._scan_official_java_runtime(runtime_path, verify=False)
            program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
            runtime_path = Path(program_files_x86) / "Minecraft Launcher/runtime"
            self._scan_official_java_runtime(runtime_path, verify=False)
        elif os_type == OperatingSystem.LINUX:
            runtime_path = Path.home() / ".minecraft/runtime"
            self._scan_official_java_runtime(runtime_path, verify=False)
        elif os_type == OperatingSystem.MACOS:
            runtime_path = Path.home() / "Library/Application Support/minecraft/runtime"
            self._scan_official_java_runtime(runtime_path, verify=False)

    def _scan_official_java_runtime(self, directory: Path, verify: bool):
        """扫描 Minecraft 官方运行时目录"""
        if not directory.is_dir():
            return
        platform_str = self._get_mojang_java_platform(Platform.current())
        if not platform_str:
            return
        for component in directory.iterdir():
            if component.is_dir():
                self._try_add_java_in_component_dir(platform_str, component, verify)

    def _try_add_java_in_component_dir(self, platform_str: str, component: Path, verify: bool):
        """扫描 Minecraft 运行时组件目录"""
        java_dir = component / platform_str / component.name
        if not java_dir.is_dir():
            return
        if verify:
            sha1_file = component / platform_str / f"{component.name}.sha1"
            if sha1_file.is_file():
                # 简单验证：检查文件是否存在，不校验哈希（耗时）
                try:
                    with sha1_file.open() as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            idx = line.find(" /#//")
                            if idx <= 0:
                                continue
                            file_path = java_dir / line[:idx]
                            if not file_path.is_file():
                                self._log(f"验证失败：缺少文件 {file_path}")
                                return
                except Exception:
                    return
        if OperatingSystem.current() == OperatingSystem.MACOS:
            mac_home = java_dir / "jre.bundle/Contents/Home"
            if mac_home.is_dir():
                self._try_add_java_home(mac_home)
                return
        self._try_add_java_home(java_dir)

    def _get_mojang_java_platform(self, platform: Platform) -> Optional[str]:
        """返回 Mojang Java 下载平台标识"""
        if platform.os == OperatingSystem.WINDOWS:
            if platform.arch == Architecture.X86:
                return "windows-x86"
            if platform.arch == Architecture.X86_64:
                return "windows-x64"
            if platform.arch == Architecture.AARCH64:
                return "windows-arm64"
        elif platform.os == OperatingSystem.LINUX:
            if platform.arch == Architecture.X86:
                return "linux-i386"
            if platform.arch == Architecture.X86_64:
                return "linux"
        elif platform.os == OperatingSystem.MACOS:
            if platform.arch == Architecture.X86_64:
                return "mac-os"
            if platform.arch == Architecture.AARCH64:
                return "mac-os-arm64"
        return None

    def _scan_path_env(self):
        """扫描 PATH 环境变量中的 java"""
        path_env = os.environ.get("PATH", "")
        for p in path_env.split(os.pathsep):
            if not p:
                continue
            # 跳过 Windows 下可能的 Oracle 公共文件路径（问题目录）
            if OperatingSystem.current() == OperatingSystem.WINDOWS and "\\common files\\oracle\\java\\" in p.lower():
                continue
            java_exe = Path(p) / OperatingSystem.current().get_java_executable()
            if java_exe.is_file():
                self._try_add_java_executable(java_exe)

    # ========== 全量扫描 ==========

    def refresh(self, use_cache: bool = True):
        """刷新所有 Java 列表，执行全平台扫描"""
        self._log("开始扫描系统中的 Java ...")
        if use_cache:
            self._load_cache()

        # 清空之前的结果（但保留用户手动添加的？这里为了完整，重新构建）
        self._java_runtimes.clear()
        self._failed_paths.clear()

        # 1. 从仓库（托管）中获取
        for platform in [Platform.current()]:
            for exe in self.repository.get_all_java(platform):
                self._try_add_java_executable(exe, is_managed=True)

        # 2. 从环境变量 JAVA_HOME
        java_home_env = os.environ.get("JAVA_HOME")
        if java_home_env:
            self._try_add_java_home(Path(java_home_env))

        # 3. 平台特定扫描
        os_type = OperatingSystem.current()
        if os_type == OperatingSystem.WINDOWS:
            self._scan_windows_registry()
            self._scan_windows_program_files()
        elif os_type == OperatingSystem.LINUX:
            self._scan_linux_common_dirs()
        elif os_type == OperatingSystem.MACOS:
            self._scan_macos_java_home_command()
            self._scan_macos_java_virtual_machines()

        # 4. 扫描 Minecraft 自带运行时
        self._scan_minecraft_bundled_runtimes()

        # 5. 扫描 PATH
        self._scan_path_env()

        # 6. 用户手动添加的路径
        for path_str in self._user_java_paths:
            try:
                self._try_add_java_executable(Path(path_str))
            except Exception:
                pass

        # 7. 添加当前运行环境的 Java（如果不在列表中且未被禁用）
        current_java = JavaRuntime.current_environment()
        if current_java and current_java.binary not in self._java_runtimes and not self.is_disabled(current_java.binary):
            self._java_runtimes[current_java.binary] = current_java

        self._save_cache()
        self._log(f"扫描完成，共找到 {len(self._java_runtimes)} 个 Java 运行时")
        return list(self._java_runtimes.values())

    # ========== 选择适合的 Java ==========

    @staticmethod
    def _choose_better(java1: Optional[JavaRuntime], java2: JavaRuntime) -> JavaRuntime:
        """选择更优的 Java（版本越新越好）"""
        if java1 is None:
            return java2
        if java1.parsed_version != java2.parsed_version:
            return java1 if java1.parsed_version > java2.parsed_version else java2
        return java1 if java1.version_number.compare_to(java2.version_number) >= 0 else java2

    def find_suitable_java(self, game_version: Optional[str] = None, force_x86: bool = False) -> Optional[JavaRuntime]:
        """
        为 Minecraft 选择合适的 Java 版本。
        :param game_version: Minecraft 版本号（如 "1.20.1", "26.1"）
        :param force_x86: 是否强制要求 x86 架构（某些旧版本需要）
        """
        def parse_minecraft_version(version_str: str) -> int:
            """
            解析 Minecraft 版本号，返回主版本号（整数）。
            规则：
              - 若以 "1." 开头，则取第二段数字（如 1.20.1 -> 20）
              - 否则取第一段数字（如 26.1 -> 26）
            """
            parts = version_str.split('.')
            if version_str.startswith("1.") and len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    return 0
            else:
                try:
                    return int(parts[0])
                except ValueError:
                    return 0

        arch = Architecture.current()
        system_arch = arch
        if force_x86:
            target_arch = Architecture.X86
        else:
            target_arch = system_arch

        # 解析 Minecraft 主版本
        mc_major = 0
        if game_version:
            mc_major = parse_minecraft_version(game_version)

        # 定义版本映射表：(Minecraft 主版本下限, 所需 Java 主版本下限)
        version_requirements = [
            (21, 21),  # Minecraft 主版本 >= 21 需要 Java 21+（示例）
            (18, 17),  # Minecraft 主版本 >= 18 需要 Java 17+
            (17, 16),  # Minecraft 主版本 >= 17 需要 Java 16+
        ]
        required_java_version = 8  # 默认最低 Java 8
        for mc_ver, java_ver in version_requirements:
            if mc_major >= mc_ver:
                required_java_version = java_ver
                break

        mandatory = None
        suggested = None

        for runtime in self._java_runtimes.values():
            # 架构匹配
            if runtime.architecture != target_arch:
                continue

            # 版本匹配
            if runtime.parsed_version < required_java_version:
                continue

            # 可选：对于旧版本（<1.17），如果 Java 版本过高可能也有兼容性问题，但通常高版本 Java 可运行旧版
            # 此处不做限制，让启动器自行决定

            mandatory = self._choose_better(mandatory, runtime)
            suggested = self._choose_better(suggested, runtime)

        return suggested if suggested else mandatory

    # ========== 获取所有 Java ==========

    def get_all_java(self) -> List[JavaRuntime]:
        return sorted(self._java_runtimes.values(), key=lambda x: x.parsed_version, reverse=True)

    def get_java_by_binary(self, binary: Path) -> Optional[JavaRuntime]:
        real = binary.resolve()
        return self._java_runtimes.get(real)

    # ========== 用户配置持久化（外部调用） ==========

    def set_user_java_paths(self, paths: List[str]):
        self._user_java_paths = set(paths)

    def set_disabled_java_paths(self, paths: List[str]):
        self._disabled_java_paths = set(paths)


# ========== 便捷函数 ==========

def create_java_manager(global_root: Optional[Path] = None, log_callback: Optional[Callable[[str], None]] = None) -> JavaManager:
    return JavaManager(global_root, log_callback)


# ========== 示例用法 ==========
if __name__ == "__main__":
    manager = create_java_manager()
    manager.refresh(use_cache=True)

    print(f"找到 {len(manager.get_all_java())} 个 Java:")
    for java in manager.get_all_java():
        print(f"  {java.binary} (版本 {java.version}, {java.vendor or 'unknown'}, {'managed' if java.is_managed else 'system'}, {java.architecture.value})")

    suitable = manager.find_suitable_java(game_version="26.1")
    if suitable:
        print(f"\n推荐的 Java: {suitable.binary} (版本 {suitable.version})")
    else:
        print("\n未找到合适的 Java")