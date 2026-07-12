from .NetLibs import BaseApiClient


class MojangClient(BaseApiClient):
    """负责与 Mojang 官方 API 交互"""

    def get_version_manifest(self) -> dict:
        """
        获取完整版本清单
        :return: 清单列表
        """
        return self._get_json_with_retry(
            f"{self.config.Meta}/mc/game/version_manifest_v2.json"
        )

    def get_version_json(self, version_id: str, sha1: str) -> dict:
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


class FabricClient(BaseApiClient):
    """负责与 Fabric 官方 API 交互"""

    def get_loaders(self, version_id: str) -> list[dict]:
        """
        获取指定某个 Minecraft 版本可用的 Fabric 版本列表
        :param version_id: 版本 ID
        :return: Fabric 版本列表
        """
        return self._get_json_with_retry(
            f"{self.config.FabricMeta}/v1/versions/loader/{version_id}"
        )

    def get_loader_profile(self, game_version_id: str, loader_version: str) -> dict:
        """
        获取一个 Fabric 版本的 Meta Json
        :param game_version_id: 游戏版本 ID
        :param loader_version: Fabric 版本 ID
        :return: Meta Json
        """
        return self._get_json_with_retry(
            f"{self.config.FabricMeta}/v2/versions/loader/{game_version_id}/{loader_version}/profile/json"
        )