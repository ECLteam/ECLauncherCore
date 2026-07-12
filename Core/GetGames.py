from Net.MetaClient import (
    MojangClient,
    FabricClient
)
from FilesChecker import FilesChecker
from pathlib import Path
import json


class VersionClassifier:
    """独立的版本分类器，可单独测试和扩展"""
    @staticmethod
    def classify(versions: dict) -> dict:
        """
        Minecraft 版本分类
        :param versions: 版本清单列表
        :return: {"分类": [版本列表], "映射": {...}}
        """
        special_fool_days = ["1.RV-Pre1"]
        release, snapshot, fool_days, beta, alpha = [], [], [], [], []
        mapping = {}
        for v in versions:
            if v["type"] == "release":
                release.append(v)
            elif v["type"] == "snapshot":
                if "-04-01" in v["releaseTime"] or v["id"] in special_fool_days:
                    fool_days.append(v)
                else:
                    snapshot.append(v)
            elif "beta" in v["type"]:
                beta.append(v)
            elif "alpha" in v["type"]:
                alpha.append(v)
            mapping.update({v["id"]: v})

        return {
            "All": versions,  # 所有版本 [{"...": "..."}]
            "Release": release,    # 正式版 [{"...": "..."}]
            "Snapshot": snapshot,  # 快照版 [{"...": "..."}]
            "FoolDays": fool_days,  # 愚人节版 [{"...": "..."}]
            "Beta": beta,  # Beta版 [{"...": "..."}]
            "Alpha": alpha,  # Alpha版 [{"...": "..."}]
            "Mapping": mapping  # 映射表 {"<版本ID>": {...}}
        }


class VersionMetadataManager:
    """负责 VersionsInfo.json 的读写和更新"""
    def __init__(self, game_path: Path):
        """
        初始化
        :param game_path: .minecraft 路径
        """
        self.info_path = game_path / "versions" / "VersionsInfo.json"

    def add_entry(self, version_id: str, metadata: dict) -> None:
        """
        写入缓存文件
        :param version_id: 版本 ID
        :param metadata: 版本信息
        :return: None
        """
        data = {}
        if self.info_path.is_file():
            data = json.loads(self.info_path.read_text("utf-8"))
        data.update({version_id: metadata})
        self.info_path.write_text(json.dumps(data, ensure_ascii=False, indent=4), encoding="utf-8")


class GetGames:
    def __init__(
        self,
        mojang_client: MojangClient,
        fabric_client: FabricClient,
        files_checker: FilesChecker,
        game_path: Path | str,
    ):
        """
        获取游戏基类
        :param mojang_client: MojangClient 实例
        :param fabric_client: FabricClient 实例
        :param files_checker: FilesChecker 实例
        :param game_path: .minecraft 路径
        """
        self.mojang = mojang_client
        self.fabric = fabric_client
        self.files_checker = files_checker
        self.game_path = Path(game_path)
        self.metadata_mgr = VersionMetadataManager(self.game_path)
        self.output_log = print

    def get_minecraft_versions(self) -> dict:
        """
        获取版本清单列表并分类和映射
        :return: {"Latest": {上一个版本},"分类": [版本列表], "映射": {...}}
        """
        manifest = self.mojang.get_version_manifest()
        return {
            "Latest": manifest["latest"],  # 上一个版本 {"release": "...", "snapshot": "..."}
            **VersionClassifier.classify(manifest["versions"])
        }

    def download_minecraft(self, version_id: str, save_name: str | None = None) -> bool:
        """
        下载指定版本的 Minecraft
        :param version_id: 版本 ID
        :param save_name: 保存名称
        :return: bool 值, 是否成功下载
        """
        save_name = save_name or version_id
        # 1. 获取版本 JSON（客户端封装了重试）
        manifest = self.get_minecraft_versions()
        target = next((v for v in manifest["versions"] if v["id"] == version_id), None)
        if not target:
            return False
        version_data = self.mojang.get_version_json(version_id, target["sha1"])

        # 2. 保存 JSON
        json_path = self.game_path / "versions" / save_name / f"{save_name}.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(version_data, indent=4), encoding="utf-8")

        # 3. 更新元数据
        self.metadata_mgr.add_entry(version_id, {
            "Type": "Vanilla",
            "Version": version_id,
            "VanillaType": target["type"]
        })

        # 4. 下载文件（调用统一检查器）
        self.files_checker.check_files(self.game_path, save_name)
        return True

