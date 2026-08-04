from urllib.parse import urlparse, urlunparse
from threading import Lock
from copy import deepcopy
from pathlib import Path
from uuid import uuid4
import httpx
import json


class YggdrasilClient:
    def __init__(self):
        self.client = httpx.Client(
            http2=True,
            timeout=httpx.Timeout(15, connect=10),
            follow_redirects=True,
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        )

    @staticmethod
    def _to_https(url: str) -> str:
        """严格实现 Authlib-Injector 标准, 将协议头改为 https"""
        parsed = urlparse(url)

        # 已有协议 → 直接替换为 https 或 无协议，但以 // 开头（如 //example.com）→ 补上 https
        if parsed.scheme or parsed.netloc:
            parsed = parsed._replace(scheme="https")
        else:
            # 完全无协议（如 example.com/path）→ 手动补全 https:// 重新解析
            parsed = urlparse(f"https://{url}")

        # 显式解包成元组，确保类型明确，避免类型检查器误报
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

    def follow_ali(self, url: str):
        """
        通过 ALI 找到 Yggdrasil 端点
        :param url: 提供 Yggdrasil 登录的网站 URL
        :return: Yggdrasil 端点
        """
        url = self._to_https(url)
        resp = self.client.head(url)
        resp.raise_for_status()
        ali_url = resp.headers.get("X-Authlib-Injector-API-Location")
        if ali_url:
            return ali_url.strip("/")
        return url.strip("/")

    def auth(self, url: str, username: str, password: str, follow_ali: bool = True, client_token: str | None = None) -> dict:
        """
        登录 Yggdrasil
        :param url: 提供 Yggdrasil 登录的网站 URL
        :param username: 用户名
        :param password: 密码
        :param follow_ali: 是否跟随 ALI
        :param client_token: 自定义客户端令牌
        :return:
        """
        root_url = self.follow_ali(url) if follow_ali else url.strip("/")
        auth_url = f"{root_url}/authserver/authenticate"
        payload = {
            "agent": {
                "name": "Minecraft",
                "version": 1
            },
            "username": username,
            "password": password,
            "clientToken": client_token or uuid4().hex,
            "requestUser": True  # 请求返回用户信息
        }

        resp = self.client.post(auth_url, json=payload)
        resp.raise_for_status()

        return resp.json()

    def validate(self, url: str, access_token: str, client_token: str, follow_ali: bool = True) -> bool:
        """
        检验令牌是否有效
        :param url: 提供 Yggdrasil 登录的网站 URL
        :param access_token: 登录令牌
        :param client_token: 客户端令牌
        :param follow_ali: 是否跟随 ALI
        :return: bool
        """
        root_url = self.follow_ali(url) if follow_ali else url.strip("/")
        validate_url = f"{root_url}/authserver/validate"

        payload = {
            "accessToken": access_token,
            "clientToken": client_token
        }

        resp = self.client.post(validate_url, json=payload)

        if resp.status_code == 204:
            return True
        return False

    def refresh(self, url: str, access_token: str, client_token: str, follow_ali: bool = True) -> dict:
        """
        :param url: 提供 Yggdrasil 登录的网站 URL
        :param access_token: 登录令牌
        :param client_token: 客户端令牌
        :param follow_ali: 是否跟随 ALI
        """
        root_url = self.follow_ali(url) if follow_ali else url.strip("/")
        refresh_url = f"{root_url}/authserver/refresh"

        payload = {
            "accessToken": access_token,
            "clientToken": client_token,
            "requestUser": True
        }

        resp = self.client.post(refresh_url, json=payload)
        resp.raise_for_status()

        return resp.json()

    def invalidate(self, url: str, access_token: str, client_token: str, follow_ali: bool = True) -> bool:
        """
        吊销指定令牌
        :param url: 提供 Yggdrasil 登录的网站 URL
        :param access_token: 登录令牌
        :param client_token: 客户端令牌
        :param follow_ali: 是否跟随 ALI
        :return: bool
        """
        root_url = self.follow_ali(url) if follow_ali else url.strip("/")
        invalidate_url = f"{root_url}/authserver/invalidate"

        payload = {
            "accessToken": access_token,
            "clientToken": client_token
        }

        resp = self.client.post(invalidate_url, json=payload)

        if resp.status_code == 204:
            return True
        return False

    def signout(self, url: str, username: str, password: str, follow_ali: bool = True) -> bool:
        """
        吊销用户的所有令牌
        :param url: 提供 Yggdrasil 登录的网站 URL
        :param username: 用户名
        :param password: 密码
        :param follow_ali: 是否跟随 ALI
        :return: bool
        """
        root_url = self.follow_ali(url) if follow_ali else url.strip("/")
        signout_url = f"{root_url}/authserver/signout"

        payload = {
            "username": username,
            "password": password
        }

        resp = self.client.post(signout_url, json=payload)

        if resp.status_code == 204:
            return True
        return False

    def close(self):
        """关闭 HTTP 客户端"""
        if hasattr(self, "client"):
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self):
        self.close()


class YggdrasilAuthManager:
    def __init__(self, cache_path: Path | str | None = None):
        self.cache_path = Path(cache_path) if cache_path else Path.home() / ".ECL"
        self.cache_path = self.cache_path / "accounts"
        self.cache_path.mkdir(parents=True, exist_ok=True)

        self.account_list_file = self.cache_path / "yggdrasil_accounts_list.json"
        self.account_cache_path = self.cache_path / "yggdrasil_accounts"
        self.account_cache_path.mkdir(parents=True, exist_ok=True)

        self.yggdrasil_accounts: dict[str, dict] = {}   # account_id -> 账户信息
        self.yggdrasil_tokens: dict[str, dict[str, str]] = {}  # account_id -> (access_token, client_token)
        self.yggdrasil_client = YggdrasilClient()

        self._lock = Lock()
        self._load_accounts()

    def _load_accounts(self) -> None:
        """从文件加载账户列表，重建 MicrosoftAuth 客户端"""
        if not self.account_list_file.is_file():
            return
        data = json.loads(self.account_list_file.read_text(encoding="utf-8"))
        for account_id, info in data.items():
            try:
                token_info_path = self.account_cache_path / f"{account_id}.json"
                if not token_info_path.is_file():
                    continue
                token_info = json.loads(
                    token_info_path.read_text(encoding="utf-8")
                )

                if not self.yggdrasil_client.validate(
                    url=info["YggdrasilAPI"],
                    access_token=token_info["AccessToken"],
                    client_token=token_info["ClientToken"],
                    follow_ali=False
                ):
                    refresh_info = self.yggdrasil_client.refresh(
                        url=info["YggdrasilAPI"],
                        access_token=token_info["AccessToken"],
                        client_token=token_info["ClientToken"],
                        follow_ali=False
                    )
                    token_info = {
                        "AccessToken": refresh_info["accessToken"],
                        "ClientToken": refresh_info["clientToken"]
                    }
                    self._save_account_cache(account_id, token_info)

                    info = {
                        "AccountId": account_id,
                        "YggdrasilAPI": info["YggdrasilAPI"],
                        "AvailableProfiles": refresh_info["availableProfiles"],
                        "SelectedProfile": refresh_info["selectedProfile"],
                        "User": refresh_info["user"]
                    }
                self.yggdrasil_tokens[account_id] = token_info
                self.yggdrasil_accounts[account_id] = info
            except:
                pass
        self._save_account_list()

    def _save_account_list(self) -> None:
        self.account_list_file.write_text(
            json.dumps(self.yggdrasil_accounts, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

    def _save_account_cache(self, account_id: str, data) -> None:
        (self.account_cache_path / f"{account_id}.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    def get_yggdrasil_accounts(self) -> dict:
        """
        返回当前所有账户信息的深拷贝
        :return: Microsoft Accounts
        """
        with self._lock:
            return deepcopy(self.yggdrasil_accounts)

    def add_yggdrasil_account(self, url: str, username: str, password: str) -> str:
        with self._lock:
            root_url = self.yggdrasil_client.follow_ali(url)

            account_id = uuid4().hex
            auth_info = self.yggdrasil_client.auth(
                url=root_url,
                username=username,
                password=password,
                follow_ali=False,
                client_token=account_id
            )
            token_info = {
                "AccessToken": auth_info["accessToken"],
                "ClientToken": auth_info["clientToken"]
            }
            self._save_account_cache(account_id, token_info)
            self.yggdrasil_tokens[account_id] = token_info

            self.yggdrasil_accounts[account_id] = {
                "AccountId": account_id,
                "YggdrasilAPI": root_url,
                "AvailableProfiles": auth_info["availableProfiles"],
                "SelectedProfile": auth_info["selectedProfile"],
                "User": auth_info["user"]
            }
            self._save_account_list()
            return account_id

    def del_yggdrasil_account(self, account_id: str) -> None:
        with self._lock:
            if account_id not in self.yggdrasil_accounts:
                raise KeyError(f"账户 '{account_id}' 不存在")

            account_info = self.yggdrasil_accounts[account_id]
            token_info = self.yggdrasil_tokens[account_id]

            try:
                self.yggdrasil_client.invalidate(
                    url=account_info["YggdrasilAPI"],
                    access_token=token_info["AccessToken"],
                    client_token=token_info["ClientToken"],
                    follow_ali=False
                )
            except:
                pass

            self.yggdrasil_accounts.pop(account_id, None)
            self.yggdrasil_tokens.pop(account_id, None)
            # 删除缓存文件（如果存在）
            (self.account_cache_path / f"{account_id}.json").unlink(missing_ok=True)
            self._save_account_list()

    def refresh_token_and_profile(self, account_id: str) -> dict:
        with self._lock:
            if account_id not in self.yggdrasil_accounts:
                raise KeyError(f"账户 '{account_id}' 不存在")

            account_info = self.yggdrasil_accounts[account_id]
            token_info = self.yggdrasil_tokens[account_id]

            refresh_info = self.yggdrasil_client.refresh(
                url=account_info["YggdrasilAPI"],
                access_token=token_info["AccessToken"],
                client_token=token_info["ClientToken"],
                follow_ali=False
            )

            token_info = {
                "AccessToken": refresh_info["accessToken"],
                "ClientToken": refresh_info["clientToken"]
            }
            self._save_account_cache(account_id, token_info)
            self.yggdrasil_tokens[account_id] = token_info

            account_info = {
                "AccountId": account_id,
                "YggdrasilAPI": account_info["YggdrasilAPI"],
                "AvailableProfiles": refresh_info["availableProfiles"],
                "SelectedProfile": refresh_info["selectedProfile"],
                "User": refresh_info["user"]
            }
            self.yggdrasil_accounts[account_id] = account_info
            self._save_account_list()
            return account_info

    def get_yggdrasil_token(self, account_id: str) -> dict:
        with self._lock:
            if account_id not in self.yggdrasil_accounts:
                raise KeyError(f"账户 '{account_id}' 不存在")

            account_info = self.yggdrasil_accounts[account_id]
            token_info = self.yggdrasil_tokens[account_id]

            if self.yggdrasil_client.validate(
                url=account_info["YggdrasilAPI"],
                access_token=token_info["AccessToken"],
                client_token=token_info["ClientToken"],
                follow_ali=False
            ):
                token_info["YggdrasilAPI"] = account_info["YggdrasilAPI"]
                return token_info

            account_info = self.refresh_token_and_profile(account_id)
            token_info = self.yggdrasil_tokens[account_id]

            token_info["YggdrasilAPI"] = account_info["YggdrasilAPI"]
            return token_info

    def close(self) -> None:
        """释放内部 HTTP 客户端资源"""
        if hasattr(self, "yggdrasil_client") and self.yggdrasil_client:
            self.yggdrasil_client.close()
            self.yggdrasil_client = None

    def __enter__(self):
        return self

    def __exit__(self):
        self.close()
