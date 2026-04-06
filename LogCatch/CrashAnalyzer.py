# 该日志解析学习了 PCL II，感谢 PCL II 项目

from typing import Callable, List, Dict, Optional, Tuple, Union
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
import tempfile
import zipfile
import shutil
import re


class CrashReason(Enum):
    # Java 相关
    JAVA_VM_PARAM = auto()
    USING_OPENJ9 = auto()
    USING_JDK = auto()
    JAVA_VERSION_HIGH = auto()
    JAVA_VERSION_INCOMPATIBLE = auto()
    USE_32BIT_JAVA = auto()
    # 内存与显卡
    OUT_OF_MEMORY = auto()
    OPENGL_NOT_SUPPORTED = auto()
    PIXEL_FORMAT_FAIL = auto()
    INTEL_DRIVER = auto()
    AMD_DRIVER = auto()
    NVIDIA_DRIVER = auto()
    TEXTURE_TOO_LARGE = auto()
    # Mod 相关
    MOD_EXTRACTED = auto()
    MIXIN_BOOTSTRAP_MISSING = auto()
    MOD_NAME_SPECIAL = auto()
    MOD_NEEDS_JAVA11 = auto()
    MOD_DUPLICATE = auto()
    MOD_INCOMPATIBLE = auto()
    MOD_MISSING_DEP = auto()
    MOD_CRASH_CONFIRMED = auto()
    MOD_CRASH_SUSPECTED = auto()
    MIXIN_FAIL = auto()
    MOD_INIT_FAIL = auto()
    MOD_CONFIG_CRASH = auto()
    TOO_MANY_IDS = auto()
    # 加载器与兼容性
    OPTIFINE_FORGE_INCOMPAT = auto()
    SHADERSMOD_OPTIFINE = auto()
    FORGE_LOW_JAVA = auto()
    JSON_MULTI_FORGE = auto()
    FORGE_INCOMPLETE = auto()
    FABRIC_ERROR = auto()
    FORGE_ERROR = auto()
    # 其他
    NIGHT_CONFIG_BUG = auto()
    FILE_VALIDATION = auto()
    SPECIFIC_BLOCK = auto()
    SPECIFIC_ENTITY = auto()
    MANUAL_DEBUG = auto()
    NO_LOG = auto()
    UNKNOWN = auto()

class CrashAnalyzer:
    """Minecraft 崩溃分析器"""

    def __init__(self, log_callback: Callable[[str], None] = print):
        self.log = log_callback
        self.temp_dir = Path(tempfile.mkdtemp(prefix="crash_analyzer_"))
        self.raw_files: List[Tuple[Path, List[str]]] = []
        self.output_files: List[Path] = []

        # 分析结果
        self.log_mc: Optional[str] = None      # latest.log
        self.log_debug: Optional[str] = None   # debug.log
        self.log_hs: Optional[str] = None      # hs_err
        self.log_crash: Optional[str] = None   # crash-report
        self.reasons: Dict[CrashReason, List[str]] = {}

    def set_output_log(self, output_function: Callable[[str], None]) -> None:
        self.log = output_function

    # ---------- 收集阶段 ----------
    def collect(self, version_path: Union[str, Path], latest_output: Optional[List[str]] = None, import_zip: Optional[str] = None):
        """收集日志文件：version_path 为版本隔离目录，latest_output 为启动器捕获的最后输出，import_zip 可导入压缩包"""
        self.log("[Crash Analyze] 开始收集日志文件")
        version_path = Path(version_path)
        possible = []

        # 标准位置
        possible.extend(version_path.glob("crash-reports/*"))
        possible.extend(version_path.parent.parent.glob("*.log"))
        possible.extend(version_path.glob("*.log"))
        possible.append(version_path / "logs" / "latest.log")
        possible.append(version_path / "logs" / "debug.log")

        # 过滤最近3分钟内的非空日志
        for p in set(possible):
            try:
                if p.exists() and p.stat().st_size > 0:
                    age = (datetime.now() - datetime.fromtimestamp(p.stat().st_mtime)).total_seconds() / 60
                    if age < 3:
                        self.raw_files.append((p, self._read_lines(p)))
                        self.log(f"  收集: {p.name}")
            except Exception:
                pass

        # 启动器最后输出
        if latest_output:
            out_path = self.temp_dir / "raw_output.log"
            self._write_lines(out_path, latest_output)
            self.raw_files.append((out_path, latest_output))
            self.log("  收集: 启动器最后输出")

        # 导入压缩包
        if import_zip:
            try:
                with zipfile.ZipFile(import_zip, 'r') as zf:
                    zf.extractall(self.temp_dir / "imported")
                for p in (self.temp_dir / "imported").rglob("*"):
                    if p.suffix.lower() in (".log", ".txt"):
                        self.raw_files.append((p, self._read_lines(p)))
                self.log(f"  从压缩包导入: {import_zip}")
            except Exception as e:
                self.log(f"  导入压缩包失败: {e}")

        self.log(f"[Crash Analyze] 收集完成，共 {len(self.raw_files)} 个文件")

    # ---------- 准备阶段 ----------
    def prepare(self) -> bool:
        """从原始文件中提取有效日志片段，返回是否有可用信息"""
        self.log("[Crash Analyze] 准备日志文本")
        # 分类并选取最新
        candidates = {"hs": [], "crash": [], "mc": [], "debug": []}
        for path, lines in self.raw_files:
            name = path.name.lower()
            if name.startswith("hs_err"):
                candidates["hs"].append((path, lines))
            elif name.startswith("crash-") or "crash" in name:
                candidates["crash"].append((path, lines))
            elif "debug" in name:
                candidates["debug"].append((path, lines))
            else:
                candidates["mc"].append((path, lines))

        # 取最新的文件
        for key in ["hs", "crash"]:
            if candidates[key]:
                newest = max(candidates[key], key=lambda x: x[0].stat().st_mtime)
                self.output_files.append(newest[0])
                if key == "hs":
                    self.log_hs = self._head_tail(newest[1], 200, 100)
                else:
                    self.log_crash = self._head_tail(newest[1], 300, 700)

        # Minecraft 日志合并
        mc_lines = []
        for path, lines in candidates["mc"]:
            self.output_files.append(path)
            mc_lines.extend(lines)
        if mc_lines:
            self.log_mc = self._head_tail(mc_lines, 1500, 500)

        # Debug 日志
        if candidates["debug"]:
            debug_path, debug_lines = candidates["debug"][0]  # 取第一个
            self.output_files.append(debug_path)
            self.log_debug = self._head_tail(debug_lines, 1000, 0)

        has_data = any([self.log_mc, self.log_hs, self.log_crash])
        self.log(f"[Crash Analyze] 准备完成: MC日志={bool(self.log_mc)}, 崩溃报告={bool(self.log_crash)}, HS日志={bool(self.log_hs)}")
        return has_data

    # ---------- 分析阶段 ----------
    def analyze(self):
        """执行分析，填充 self.reasons"""
        self.log("[Crash Analyze] 开始分析崩溃原因")
        if not any([self.log_mc, self.log_hs, self.log_crash]):
            self._add_reason(CrashReason.NO_LOG)
            return

        full_log = (self.log_mc or "") + (self.log_debug or "") + (self.log_hs or "") + (self.log_crash or "")
        # 1. 高优先级匹配
        self._match_high_priority(full_log)
        if self.reasons:
            return
        # 2. 堆栈分析 (如果安装了模组)
        if any(k in full_log for k in ("orge", "abric", "uilt", "iteloader")):
            keywords = self._extract_stack_keywords(full_log)
            if keywords:
                mods = self._match_mod_names(keywords)
                if mods:
                    self._add_reason(CrashReason.MOD_CRASH_SUSPECTED, mods)
                else:
                    self._add_reason(CrashReason.UNKNOWN, keywords)
                return
        # 3. 低优先级匹配
        self._match_low_priority(full_log)

    # ---------- 输出阶段 ----------
    def get_summary(self) -> str:
        """获取分析结果摘要"""
        if not self.reasons:
            return "未能找到明确的崩溃原因。请检查日志文件是否完整。\n你可以尝试将错误报告发给他人寻求帮助。"

        lines = []
        for reason, details in self.reasons.items():
            text = self._reason_text(reason, details)
            lines.append(text)
        return "\n\n".join(lines)

    def get_all_log(self) -> dict[str, str | None]:
        return {
            "latest.log": (self.log_mc or None),
            "debug.log": (self.log_debug or None),
            "hs_err": (self.log_hs or None),
            "crash-report": (self.log_crash or None)
        }

    def export_report(self, zip_path: Union[str, Path]) -> bool:
        """导出完整报告为 ZIP 文件"""
        try:
            report_dir = self.temp_dir / "report"
            report_dir.mkdir(exist_ok=True)
            for src in self.output_files:
                if src.exists():
                    dst = report_dir / src.name
                    shutil.copy2(src, dst)
            # 添加分析结果
            summary = self.get_summary()
            (report_dir / "analysis_results.txt").write_text(summary, encoding="utf-8")
            # 打包
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for f in report_dir.iterdir():
                    zf.write(f, arcname=f.name)
            self.log(f"[Crash Analyze] 报告已导出: {zip_path}")
            return True
        except Exception as e:
            self.log(f"[Crash Analyze] 导出失败: {e}")
            return False

    # ---------- 内部辅助 ----------
    @staticmethod
    def _read_lines(path: Path) -> List[str]:
        try:
            return path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except:
            return []

    @staticmethod
    def _write_lines(path: Path, lines: List[str]):
        path.write_text("\n".join(lines), encoding="utf-8")

    @staticmethod
    def _head_tail(lines: List[str], head: int, tail: int) -> str:
        if len(lines) <= head + tail:
            return "\n".join(lines)
        seen = set()
        result = []
        for line in lines:
            if line in seen:
                continue
            seen.add(line)
            result.append(line)
            if len(result) >= head:
                break
        # 从尾部添加不重复的行
        tail_added = 0
        for line in reversed(lines):
            if line in seen:
                continue
            seen.add(line)
            result.insert(head, line)
            tail_added += 1
            if tail_added >= tail:
                break
        return "\n".join(filter(None, result))

    def _add_reason(self, reason: CrashReason, details: Optional[List[str]] = None):
        if reason not in self.reasons:
            self.reasons[reason] = details or []
        else:
            self.reasons[reason].extend(details or [])
        self.log(f"发现原因: {self._reason_text(reason, details or [], short=True)}")

    def _match_high_priority(self, text: str):
        # 使用字典存储 (pattern, reason, extract_group, need_flag)
        patterns = [
            (r"Unrecognized option:", CrashReason.JAVA_VM_PARAM, None, 0),
            (r"The directories below appear to be extracted jar files", CrashReason.MOD_EXTRACTED, None, 0),
            (r"Extracted mod jars found", CrashReason.MOD_EXTRACTED, None, 0),
            (r"java\.lang\.OutOfMemoryError", CrashReason.OUT_OF_MEMORY, None, 0),
            (r"Open J9 is not supported|OpenJ9 is incompatible", CrashReason.USING_OPENJ9, None, 0),
            (r"java\.lang\.ClassCastException: (java\.base/)?jdk", CrashReason.USING_JDK, None, 0),
            (r"because module java\.base does not export", CrashReason.JAVA_VERSION_HIGH, None, 0),
            (r"Unsupported class file major version", CrashReason.JAVA_VERSION_INCOMPATIBLE, None, 0),
            (r"ClassNotFoundException: org\.spongepowered\.asm\.launch\.MixinTweaker", CrashReason.MIXIN_BOOTSTRAP_MISSING, None, 0),
            (r"The driver does not appear to support OpenGL", CrashReason.OPENGL_NOT_SUPPORTED, None, 0),
            (r"Couldn't set pixel format", CrashReason.PIXEL_FORMAT_FAIL, None, 0),
            (r"EXCEPTION_ACCESS_VIOLATION.*# C  \[ig", CrashReason.INTEL_DRIVER, None, re.DOTALL),
            (r"EXCEPTION_ACCESS_VIOLATION.*# C  \[atio", CrashReason.AMD_DRIVER, None, re.DOTALL),
            (r"EXCEPTION_ACCESS_VIOLATION.*# C  \[nvoglv", CrashReason.NVIDIA_DRIVER, None, re.DOTALL),
            (r"OptiFine.*Forge.*incompatible", CrashReason.OPTIFINE_FORGE_INCOMPAT, None, re.I),
            (r"Shaders Mod detected", CrashReason.SHADERSMOD_OPTIFINE, None, 0),
            (r"java\.lang\.NoSuchMethodError: sun\.security\.util\.ManifestEntryVerifier", CrashReason.FORGE_LOW_JAVA, None, 0),
            (r"Found multiple arguments for option fml\.forgeVersion", CrashReason.JSON_MULTI_FORGE, None, 0),
            (r"Manually triggered debug crash", CrashReason.MANUAL_DEBUG, None, 0),
            (r"class file version 55\.0.*only recognizes class file versions up to", CrashReason.MOD_NEEDS_JAVA11, None, 0),
            (r"Invalid module name: '' is not a Java identifier", CrashReason.MOD_NAME_SPECIAL, None, 0),
            (r"Maybe try a lower resolution resourcepack", CrashReason.TEXTURE_TOO_LARGE, None, 0),
            (r"com\.electronwill\.nightconfig.*ParsingException", CrashReason.NIGHT_CONFIG_BUG, None, 0),
            (r"maximum id range exceeded", CrashReason.TOO_MANY_IDS, None, 0),
            (r"signer information does not match", CrashReason.FILE_VALIDATION, None, 0),
            (r"Cannot find launch target fmlclient", CrashReason.FORGE_INCOMPLETE, None, 0),
        ]
        for pat, reason, group, flags in patterns:
            if re.search(pat, text, flags):
                self._add_reason(reason)
                return  # 高优先级只取第一个

        # 需要提取附加信息的模式
        # 确定 Mod 导致崩溃
        m = re.search(r"Caught exception from ([^\n]+)", text)
        if m:
            self._add_reason(CrashReason.MOD_CRASH_CONFIRMED, [m.group(1)])
            return
        # Mod 重复安装
        m = re.search(r"DuplicateModsFoundException|Found a duplicate mod|Found duplicate mods", text)
        if m:
            self._add_reason(CrashReason.MOD_DUPLICATE)
            return
        # 缺少前置
        m = re.search(r"Missing or unsupported mandatory dependencies:[\s\S]+?([^\n]+)", text, re.DOTALL)
        if m:
            self._add_reason(CrashReason.MOD_MISSING_DEP, [m.group(1).strip()])
            return

    def _match_low_priority(self, text: str):
        # 低优先级匹配
        patterns = [
            (r"java\.lang\.NoSuchFieldException: ucp", CrashReason.JAVA_VERSION_HIGH),
            (r"Pixel format not accelerated", CrashReason.PIXEL_FORMAT_FAIL),
            (r"Invalid maximum heap size", CrashReason.USE_32BIT_JAVA),
            (r"Could not reserve enough space for \d+KB object heap", CrashReason.USE_32BIT_JAVA),
            (r"Could not reserve enough space", CrashReason.OUT_OF_MEMORY),
            (r"Block location: World: \(.*\)", CrashReason.SPECIFIC_BLOCK),
            (r"Entity's Exact location: .*", CrashReason.SPECIFIC_ENTITY),
        ]
        for pat, reason in patterns:
            if re.search(pat, text, re.I):
                self._add_reason(reason)

        # Forge/Fabric 报错
        if "A potential solution has been determined" in text:
            self._add_reason(CrashReason.FABRIC_ERROR)
        if "An exception was thrown, the game will display an error screen" in text:
            self._add_reason(CrashReason.FORGE_ERROR)

    @staticmethod
    def _extract_stack_keywords(text: str) -> List[str]:
        """从堆栈中提取可能的关键词（类名、包名片段）"""
        matches = re.findall(r"at ([a-zA-Z_][\w.]+)\.", text)
        keywords = set()
        for full in matches:
            parts = full.split('.')
            for part in parts[-3:]:
                if len(part) > 2 and part not in ("net", "com", "org", "java", "io", "util", "api", "mod", "fabric", "forge", "minecraft"):
                    keywords.add(part)
        return list(keywords)

    def _match_mod_names(self, keywords: List[str]) -> List[str]:
        """尝试在日志中查找与关键词相关的 Mod 文件名"""
        mod_names = []
        log_text = (self.log_debug or "") + (self.log_crash or "")
        for kw in keywords:
            pattern = rf"[\w\-]+\.jar.*{re.escape(kw)}"
            m = re.search(pattern, log_text, re.I)
            if m:
                jar = re.search(r"([\w\-]+\.jar)", m.group(0))
                if jar:
                    mod_names.append(jar.group(1))
        return list(dict.fromkeys(mod_names))

    @staticmethod
    def _reason_text(reason: CrashReason, details: List[str] = None, short: bool = False) -> str:
        """返回中文描述，short=True 用于日志简短输出"""
        if short:
            # 简短原因（用于日志）
            short_map = {
                CrashReason.JAVA_VM_PARAM: "Java虚拟机参数错误",
                CrashReason.MOD_EXTRACTED: "Mod被解压",
                CrashReason.OUT_OF_MEMORY: "内存不足",
                CrashReason.USING_OPENJ9: "使用了OpenJ9",
                CrashReason.USING_JDK: "使用了JDK而非JRE",
                CrashReason.JAVA_VERSION_HIGH: "Java版本过高",
                CrashReason.JAVA_VERSION_INCOMPATIBLE: "Java版本不兼容",
                CrashReason.USE_32BIT_JAVA: "使用了32位Java",
                CrashReason.MIXIN_BOOTSTRAP_MISSING: "缺少MixinBootstrap",
                CrashReason.OPENGL_NOT_SUPPORTED: "OpenGL不支持",
                CrashReason.PIXEL_FORMAT_FAIL: "像素格式设置失败",
                CrashReason.INTEL_DRIVER: "Intel显卡驱动问题",
                CrashReason.AMD_DRIVER: "AMD显卡驱动问题",
                CrashReason.NVIDIA_DRIVER: "NVIDIA显卡驱动问题",
                CrashReason.OPTIFINE_FORGE_INCOMPAT: "OptiFine与Forge不兼容",
                CrashReason.SHADERSMOD_OPTIFINE: "ShadersMod与OptiFine冲突",
                CrashReason.FORGE_LOW_JAVA: "低版本Forge与高版本Java不兼容",
                CrashReason.JSON_MULTI_FORGE: "版本JSON中存在多个Forge",
                CrashReason.MANUAL_DEBUG: "手动调试崩溃",
                CrashReason.MOD_NEEDS_JAVA11: "模组需要Java11",
                CrashReason.MOD_NAME_SPECIAL: "模组文件名含特殊字符",
                CrashReason.TEXTURE_TOO_LARGE: "材质过大或显存不足",
                CrashReason.NIGHT_CONFIG_BUG: "NightConfig错误",
                CrashReason.TOO_MANY_IDS: "模组数量超过ID限制",
                CrashReason.FILE_VALIDATION: "文件校验失败",
                CrashReason.FORGE_INCOMPLETE: "Forge安装不完整",
                CrashReason.SPECIFIC_BLOCK: "特定方块导致崩溃",
                CrashReason.SPECIFIC_ENTITY: "特定实体导致崩溃",
                CrashReason.MOD_DUPLICATE: "模组重复安装",
                CrashReason.MOD_INCOMPATIBLE: "模组不兼容",
                CrashReason.MOD_MISSING_DEP: "缺少前置模组",
                CrashReason.MOD_CRASH_CONFIRMED: "确定导致崩溃的模组",
                CrashReason.MOD_CRASH_SUSPECTED: "疑似导致崩溃的模组",
                CrashReason.MIXIN_FAIL: "Mixin注入失败",
                CrashReason.MOD_INIT_FAIL: "模组初始化失败",
                CrashReason.MOD_CONFIG_CRASH: "模组配置文件损坏",
                CrashReason.FABRIC_ERROR: "Fabric加载器报错",
                CrashReason.FORGE_ERROR: "Forge加载器报错",
                CrashReason.NO_LOG: "未找到日志文件",
                CrashReason.UNKNOWN: "未知原因",
            }
            return short_map.get(reason, "未知")
        # 详细描述（用于最终报告）
        detail_str = f"（{', '.join(details)}）" if details else ""
        texts = {
            CrashReason.JAVA_VM_PARAM: "Java虚拟机参数错误，请检查启动设置中的JVM参数。",
            CrashReason.MOD_EXTRACTED: "检测到Mod文件被解压，请删除解压后的文件夹，直接使用jar文件。",
            CrashReason.OUT_OF_MEMORY: "内存不足。请分配更多内存（建议2G以上），关闭其他程序，或降低游戏设置。",
            CrashReason.USING_OPENJ9: "OpenJ9与Minecraft不兼容，请更换为标准Java（如HotSpot）。",
            CrashReason.USING_JDK: "请使用JRE 8（Java运行环境）而非JDK（开发工具包）。",
            CrashReason.JAVA_VERSION_HIGH: "Java版本过高，建议使用Java 8。",
            CrashReason.JAVA_VERSION_INCOMPATIBLE: "Java版本不兼容，请更换为合适的Java版本（通常是Java 8或17）。",
            CrashReason.USE_32BIT_JAVA: "使用了32位Java，无法分配足够内存。请安装64位Java。",
            CrashReason.MIXIN_BOOTSTRAP_MISSING: "缺少MixinBootstrap模组，请安装后再试。",
            CrashReason.OPENGL_NOT_SUPPORTED: "显卡不支持OpenGL，请更新显卡驱动。",
            CrashReason.PIXEL_FORMAT_FAIL: "显卡驱动问题，请更新或回退显卡驱动。",
            CrashReason.INTEL_DRIVER: "Intel显卡驱动不兼容，请更新驱动或尝试降级Java版本。",
            CrashReason.AMD_DRIVER: "AMD显卡驱动不兼容，请更新驱动或尝试降级Java版本。",
            CrashReason.NVIDIA_DRIVER: "NVIDIA显卡驱动不兼容，请更新驱动或尝试降级Java版本。",
            CrashReason.OPTIFINE_FORGE_INCOMPAT: "OptiFine与Forge不兼容，请更换OptiFine版本或使用其他优化模组。",
            CrashReason.SHADERSMOD_OPTIFINE: "请勿同时安装ShadersMod和OptiFine，OptiFine已内置光影功能。",
            CrashReason.FORGE_LOW_JAVA: "低版本Forge不兼容高版本Java，请降级Java至8u320以下，或升级Forge。",
            CrashReason.JSON_MULTI_FORGE: "版本JSON中存在多个Forge条目，请重新安装Forge。",
            CrashReason.MANUAL_DEBUG: "这是玩家手动触发的调试崩溃，并非游戏错误。",
            CrashReason.MOD_NEEDS_JAVA11: "部分模组需要Java 11，请更换Java版本至11或更高。",
            CrashReason.MOD_NAME_SPECIAL: "Mod文件名包含特殊字符，请重命名，只保留字母、数字、点、减号、下划线。",
            CrashReason.TEXTURE_TOO_LARGE: "材质分辨率过高或显卡显存不足，请移除高清材质包。",
            CrashReason.NIGHT_CONFIG_BUG: "Night Config模组存在Bug，可以尝试安装Night Config Fixes。",
            CrashReason.TOO_MANY_IDS: "模组数量过多，超出游戏ID限制。请安装JEID等修复模组或减少模组。",
            CrashReason.FILE_VALIDATION: "文件校验失败，请重新下载游戏或使用VPN下载。",
            CrashReason.FORGE_INCOMPLETE: "Forge安装不完整，请重新安装Forge。",
            CrashReason.SPECIFIC_BLOCK: f"特定方块导致崩溃{detail_str}，尝试删除该方块或回档。",
            CrashReason.SPECIFIC_ENTITY: f"特定实体导致崩溃{detail_str}，尝试移除该实体或回档。",
            CrashReason.MOD_DUPLICATE: f"存在重复的Mod{detail_str}，请删除重复文件。",
            CrashReason.MOD_INCOMPATIBLE: f"Mod不兼容{detail_str}，请检查版本或删除冲突模组。",
            CrashReason.MOD_MISSING_DEP: f"缺少前置模组{detail_str}，请安装所需前置。",
            CrashReason.MOD_CRASH_CONFIRMED: f"模组 {', '.join(details) if details else '未知'} 导致崩溃，请尝试禁用或更新该模组。",
            CrashReason.MOD_CRASH_SUSPECTED: f"疑似模组 {', '.join(details) if details else '未知'} 导致崩溃，请尝试禁用排查。",
            CrashReason.MIXIN_FAIL: f"Mixin注入失败{detail_str}，通常由不兼容模组引起，请逐步禁用模组排查。",
            CrashReason.MOD_INIT_FAIL: f"模组初始化失败{detail_str}，请检查模组版本或依赖。",
            CrashReason.MOD_CONFIG_CRASH: f"模组配置文件损坏{detail_str}，请删除配置文件让游戏重新生成。",
            CrashReason.FABRIC_ERROR: "Fabric加载器报告错误，请查看日志中的详细提示。",
            CrashReason.FORGE_ERROR: "Forge加载器报告错误，请查看日志中的详细提示。",
            CrashReason.NO_LOG: "未找到任何日志文件，无法分析。",
            CrashReason.UNKNOWN: f"堆栈中出现关键词: {', '.join(details) if details else '未知'}，请将错误报告发给他人分析。",
        }
        return texts.get(reason, "未知错误原因。")

    def __del__(self):
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass


"""def main():
    analyzer = CrashAnalyzer()
    # 收集日志
    analyzer.collect(r"path")
    # 如果有启动器捕获的最后输出
    # analyzer.collect(version_path, latest_output=last_console_lines)
    # 准备并分析
    if analyzer.prepare():
        analyzer.analyze()
        print(analyzer.get_summary())
        # 导出报告
        analyzer.export_report("crash_report.zip")"""
