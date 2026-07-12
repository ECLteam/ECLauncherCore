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
        self._client = httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=True,
            headers={"User-Agent": "EuoraCraft-Launcher"},
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=40)
        )

    def _get_json_with_retry(self, url: str):
        """带重试的 GET JSON 方法，供子类复用"""
        for attempt in range(self.max_retries):
            try:
                resp = self._client.get(url)
                resp.raise_for_status()
                return resp.json()
            except (httpx.HTTPError, httpx.StreamError):
                if attempt == self.max_retries - 1:
                    raise
                t_sleep(2 ** attempt)
        raise RuntimeError(f"请求失败: {url}")

    def close(self) -> None:
        """
        销毁实例
        :return: None
        """
        self._client.close()


class RepositoryResolver:
    """
    根据依赖的 URL 或路径，决定最终使用的仓库地址。
    职责单一，扩展新加载器只需修改此处。
    """

    def __init__(self, config: ApiUrlConfig):
        """
        初始化
        :param config: ApiUrlConfig 实例
        """
        self.config = config

    def resolve(self, url: str, path: str) -> str:
        """
        返回最匹配的仓库基础 URL
        :param url: URL
        :param path: Path
        :return: API URL
        """
        combined = (url + path).lower()

        if "fabric" in combined:
            return self.config.Fabric
        if "neoforged" in combined or "neoforge" in combined:
            return self.config.NeoForged
        if "forge" in combined:
            return self.config.Forge
        if "quilt" in combined:
            return self.config.Quilt
        # 默认回退到官方 libraries 仓库
        return self.config.Libraries