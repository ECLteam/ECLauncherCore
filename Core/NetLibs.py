from dataclasses import dataclass, fields, asdict
from time import sleep as t_sleep
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

    def close(self) -> None:
        """
        销毁实例
        :return: None
        """
        self._client.close()
