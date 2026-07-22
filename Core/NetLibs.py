from dataclasses import dataclass, fields, asdict
from time import sleep as t_sleep
from pathlib import Path
import httpx


@dataclass
class ApiUrlConfig:
    """
    一些 API 的 URL
    """
    Meta: str = "https://launchermeta.mojang.com"
    Data: str = "https://launcher.mojang.com"
    Libraries: str = "https://libraries.minecraft.net"
    Assets: str = "https://resources.download.minecraft.net"
    Forge: str = "https://files.minecraftforge.net/maven"
    Fabric: str = "https://maven.fabricmc.net"
    FabricMeta: str = "https://meta.fabricmc.net"
    NeoForged: str = "https://maven.neoforged.net/releases"
    Quilt: str = "https://maven.quiltmc.org"
    QuiltMeta: str = "https://meta.quiltmc.org"

    def get(self, key_name: str)-> str | None:
        """
        通过元素名称查找值
        :param key_name: 元素名称
        :return: 对应值
        """
        return getattr(self, key_name, None)

    def to_dict(self) -> dict[str, str]:
        """
        转为字典
        :return: {"API": "URL"}
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, api_url_dict: dict) -> "ApiUrlConfig":
        """
        从字典创建实例, 不存在的键值则默认
        :param api_url_dict: {"API": "URL"}
        :return: ApiUrlConfig 实例
        """
        kw = {}
        for api_name in fields(cls):
            if api_name.name in api_url_dict: kw.update({api_name.name: api_url_dict[api_name.name].strip("/")})
        return cls(**kw)

    def update_from_dict(self, api_url_dict: dict) -> None:
        """
        从字典中更新元素值
        :param api_url_dict: {"API": "URL"}
        :return: Nome
        """
        for api_name in fields(self):
            if api_name.name in api_url_dict: setattr(self, api_name.name, api_url_dict[api_name.name].strip("/"))


@dataclass
class BmclApiUrl(ApiUrlConfig):
    """
    一些 BMCLAPI 的 URL
    """
    Meta: str = "https://bmclapi2.bangbang93.com"
    Data: str = "https://bmclapi2.bangbang93.com"
    Libraries: str = "https://bmclapi2.bangbang93.com/maven"
    Assets: str = "https://bmclapi2.bangbang93.com/assets"
    Forge: str = "https://bmclapi2.bangbang93.com/maven"
    Fabric: str = "https://bmclapi2.bangbang93.com/maven"
    FabricMeta: str = "https://bmclapi2.bangbang93.com/fabric-meta"
    NeoForged: str = "https://bmclapi2.bangbang93.com/maven"
    Quilt: str = "https://bmclapi2.bangbang93.com/maven"
    QuiltMeta: str = "https://bmclapi2.bangbang93.com/quilt-meta"


class BaseApiClient:
    """所有 API 客户端的基类，统一管理 httpx 客户端和重试"""
    def __init__(self, config: ApiUrlConfig, max_retries: int = 3):
        """
        初始化
        :param config: ApiUrlConfig 实例
        :param max_retries: 最大重试次数
        """
        self.config = config
        self.max_retries = max_retries
        self.headers = {"Content-Type": "application/json", "User-Agent": "EuoraCraft-Launcher"}
        self._client = httpx.Client(
            http2=True,
            timeout=httpx.Timeout(15, connect=10),
            follow_redirects=True,
            headers=self.headers,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=40)
        )

    def _get_json_with_retry(self,
             url: str,
             data: dict | None = None,
             headers: dict | None = None
         ):
        """带重试的 GET JSON 方法，供子类复用"""
        headers = headers or self.headers
        for attempt in range(self.max_retries):
            try:
                resp = self._client.get(url, params=data, headers=headers)
                resp.raise_for_status()
                return resp.json()
            except (httpx.HTTPError, httpx.StreamError):
                if attempt == self.max_retries - 1:
                    break
                t_sleep(2 ** attempt)
        raise RuntimeError(f"请求失败: {url}")

    def _download_with_retry(self,
             url: str,
             data: dict | None = None,
             headers: dict | None = None
         ) -> bytes:
        """带重试的单文件下载方法，供子类复用"""
        headers = headers or self.headers
        for attempt in range(self.max_retries):
            try:
                resp = self._client.get(url, params=data, headers=headers)
                resp.raise_for_status()
                return resp.content
            except (httpx.HTTPError, httpx.StreamError):
                if attempt == self.max_retries - 1:
                    break
                t_sleep(2 ** attempt)
        raise RuntimeError(f"下载失败: {url}")

    def get_minecraft_manifest(self) -> dict:
        """
        获取完整版本清单
        :return: 清单列表
        """
        return self._get_json_with_retry(
            f"{self.config.Meta}/mc/game/version_manifest_v2.json"
        )

    def get_minecraft_json(self, version_id: str, sha1: str) -> dict:
        """
        获取某个版本的 Meta JSON
        :param version_id: 版本 ID
        :param sha1: Json 的 Sha1
        :return:
        """
        return self._get_json_with_retry(
            f"{self.config.Meta}/v1/packages/{sha1}/{version_id}.json"
        )

    def get_asset_index(self, asset_id: str, sha1: str) -> dict:
        """
        获取资源索引文件
        :param asset_id: 资源引索 ID
        :param sha1: Json 的 Sha1
        """
        return self._get_json_with_retry(
            f"{self.config.Meta}/v1/packages/{sha1}/{asset_id}.json"
        )

    def get_client_jar_url(self, sha1: str) -> str:
        """
        获取客户端 Jar 文件的直接下载 URL
        :param sha1: Jar 文件的 Sha1
        :return: Jar URL
        """
        return f"{self.config.Data}/v1/objects/{sha1}/client.jar"

    def download_client_jar(self, sha1: str, save_path: Path | str) -> None:
        save_path = Path(save_path)
        save_path.write_bytes(self._download_with_retry(self.get_client_jar_url(sha1)))

    def get_fabric_versions(self, version_id: str) -> list[dict]:
        """
        获取指定某个 Minecraft 版本可用的 Fabric 版本列表
        :param version_id: 版本 ID
        :return: Fabric 版本列表
        """
        return self._get_json_with_retry(
            f"{self.config.FabricMeta}/v2/versions/loader/{version_id}"
        )

    def get_fabric_profile(self, game_version_id: str, loader_version: str) -> dict:
        """
        获取一个 Fabric 版本的 Meta Json
        :param game_version_id: 游戏版本 ID
        :param loader_version: Fabric 版本 ID
        :return: Meta Json
        """
        return self._get_json_with_retry(
            f"{self.config.FabricMeta}/v2/versions/loader/{game_version_id}/{loader_version}/profile/json"
        )

    def get_neoforged_versions(self, game_version_id: str) -> dict[str, list]:
        all_ver = []
        beta_ver = []
        alpha_ver = []
        if type(self.config) == BmclApiUrl:
            ver_list = self._get_json_with_retry(
                f"https://bmclapi2.bangbang93.com/neoforge/list/{game_version_id}"
            )
            if ver_list:
                for version in ver_list:
                    ver_name = version["version"]
                    ver_info = {
                        "LoaderVersion": ver_name,
                        "GameVersion": version["mcversion"],
                        "LoaderType": "Stable"
                    }
                    if "beta" in ver_name:
                        ver_info["LoaderType"] = "Beta"
                        beta_ver.append(ver_info)
                    elif "alpha" in ver_name:
                        ver_info["LoaderType"] = "Alpha"
                        alpha_ver.append(ver_info)
                    all_ver.append(ver_info)
        else:
            payload = {"sorted": False}
            if game_version_id == "1.20.1":
                ver_list = self._get_json_with_retry(
                    "https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/forge",
                    data=payload,
                )["versions"]
                ver_list.reverse()
                for version in ver_list:
                    ver_info = {
                        "LoaderVersion": version,
                        "GameVersion": game_version_id,
                        "LoaderType": "Stable"
                    }
                    if "beta" in version:
                        ver_info["LoaderType"] = "Beta"
                        beta_ver.append(ver_info)
                    elif "alpha" in version:
                        ver_info["LoaderType"] = "Alpha"
                        alpha_ver.append(ver_info)
                    all_ver.append(ver_info)

            else:
                ver_list = self._get_json_with_retry(
                    "https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/neoforge",
                    data=payload
                )["versions"]
                ver_list.reverse()
                if game_version_id.startswith("1."):
                    game_version_id = game_version_id.replace("1.", "", 1)
                for version in ver_list:
                    if version.startswith(game_version_id):
                        ver_info = {
                            "LoaderVersion": version,
                            "GameVersion": game_version_id,
                            "LoaderType": "Stable"
                        }
                        if "beta" in version:
                            ver_info["LoaderType"] = "Beta"
                            beta_ver.append(ver_info)
                        elif "alpha" in version:
                            ver_info["LoaderType"] = "Alpha"
                            alpha_ver.append(ver_info)
                        all_ver.append(ver_info)
        return {
            "All": all_ver,
            "Beta": beta_ver,
            "Alpha": alpha_ver
        }

    def download_neoforged_installer(self, game_version_id: str, loader_version: str, save_path: Path | str):
        save_path = Path(save_path)
        if type(self.config) == BmclApiUrl:
            url = f"https://bmclapi2.bangbang93.com/neoforge/version/{loader_version}/download/installer.jar"
        elif game_version_id == "1.20.1":
            url = f"https://maven.neoforged.net/releases/net/neoforged/forge/{loader_version}/forge-{loader_version}-installer.jar"
        else:
            url = f"https://maven.neoforged.net/releases/net/neoforged/neoforge/{loader_version}/neoforge-{loader_version}-installer.jar"

        save_path = save_path / f"neoforge-{loader_version}-installer.jar"
        save_path.write_bytes(self._download_with_retry(url))

        return save_path

    def close(self) -> None:
        """
        销毁实例
        :return: None
        """
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self):
        self.close()

