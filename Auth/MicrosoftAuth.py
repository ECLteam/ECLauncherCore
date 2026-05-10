import json
import os
import uuid
from pathlib import Path
from typing import Optional, Dict, Tuple, Callable, List

import msal
import requests


class MinecraftAccount:
    """Minecraft 账户数据类"""
    def __init__(self, alias: str, account_id: str, email: str, profile: dict, cache_file: str):
        self.alias = alias
        self.account_id = account_id
        self.email = email
        self.profile = profile
        self.cache_file = cache_file
        self.skin_url = profile.get("skins", [{}])[0].get("url", "") if profile.get("skins") else ""
        self.skin_cache_path = ""

    def to_dict(self) -> dict:
        return {
            "alias": self.alias,
            "account_id": self.account_id,
            "email": self.email,
            "profile": self.profile,
            "cache_file": self.cache_file,
            "skin_url": self.skin_url,
            "skin_cache_path": self.skin_cache_path,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MinecraftAccount":
        acc = cls(
            alias=data["alias"],
            account_id=data["account_id"],
            email=data["email"],
            profile=data["profile"],
            cache_file=data["cache_file"],
        )
        acc.skin_url = data.get("skin_url", "")
        acc.skin_cache_path = data.get("skin_cache_path", "")
        return acc


class MultiAccountMinecraftAuth:
    """Minecraft 多账户认证管理器（明文存储，简化版）"""

    def __init__(self, client_id: str, data_dir: str = "~/.ECLAuth"):
        self.client_id = client_id
        self.data_dir = Path(os.path.expanduser(data_dir))
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # 回调函数
        self._log_callback: Callable[[str], None] = print
        self._login_log_callback: Callable[[str], None] = print
        self._login_callback: Callable[[dict], None] = self._default_login_callback

        # 数据存储
        self.accounts: Dict[str, MinecraftAccount] = {}
        self.current_account: Optional[MinecraftAccount] = None
        self.accounts_file = self.data_dir / "accounts.json"
        self.current_account_file = self.data_dir / "current_account.txt"

        self._load_accounts()

    # ==================== 回调设置 ====================
    def set_output_log(self, func: Callable[[str], None]) -> None:
        self._log_callback = func

    def set_output_login_log(self, func: Callable[[str], None]) -> None:
        self._login_log_callback = func

    def set_login_callback(self, func: Callable[[dict], None]) -> None:
        self._login_callback = func

    def _log(self, msg: str) -> None:
        self._log_callback(msg)

    @staticmethod
    def _default_login_callback(flow: dict):
        print(f"请在浏览器访问：{flow['verification_uri']}，并输入代码：{flow['user_code']}")

    # ==================== 账户存储 ====================
    def _load_accounts(self) -> None:
        """加载账户（明文）"""
        if not self.accounts_file.exists():
            return
        try:
            with open(self.accounts_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for account_id, acc_dict in data.items():
                    self.accounts[account_id] = MinecraftAccount.from_dict(acc_dict)
            self._log(f"已加载 {len(self.accounts)} 个账户")
        except Exception as e:
            self._log(f"加载账户失败: {e}")

        # 加载当前账户
        if self.current_account_file.exists():
            try:
                current_id = self.current_account_file.read_text().strip()
                if current_id in self.accounts:
                    self.current_account = self.accounts[current_id]
                    self._log(f"当前账户: {self.current_account.alias}")
            except Exception as e:
                self._log(f"加载当前账户失败: {e}")

    def _save_accounts(self) -> None:
        """保存账户（明文）"""
        data = {aid: acc.to_dict() for aid, acc in self.accounts.items()}
        try:
            with open(self.accounts_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._log(f"保存账户失败: {e}")

    def _set_current_account(self, account: MinecraftAccount) -> None:
        self.current_account = account
        try:
            self.current_account_file.write_text(account.account_id)
        except Exception as e:
            self._log(f"保存当前账户失败: {e}")

    # ==================== 令牌缓存（明文） ====================
    def _get_cache_path(self, cache_file: str) -> Path:
        cache_dir = self.data_dir / "cache"
        cache_dir.mkdir(exist_ok=True)
        return cache_dir / f"{cache_file}.json"

    def _load_token_cache(self, cache_file: str) -> msal.SerializableTokenCache:
        cache_path = self._get_cache_path(cache_file)
        token_cache = msal.SerializableTokenCache()
        if cache_path.exists():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    data = f.read()
                    token_cache.deserialize(data)
            except Exception as e:
                self._log(f"加载令牌缓存失败: {e}")
        token_cache.cache_path = str(cache_path)
        return token_cache

    def _save_token_cache(self, token_cache: msal.SerializableTokenCache) -> None:
        if not hasattr(token_cache, 'cache_path') or not token_cache.cache_path:
            return
        try:
            with open(token_cache.cache_path, 'w', encoding='utf-8') as f:
                f.write(token_cache.serialize())
        except Exception as e:
            self._log(f"保存令牌缓存失败: {e}")

    # ==================== 认证流程 ====================
    def _get_microsoft_token(self, cache_file: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """获取微软令牌，返回 (access_token, account_id, email)"""
        scope = ["XboxLive.signin"]
        token_cache = self._load_token_cache(cache_file)
        app = msal.PublicClientApplication(
            client_id=self.client_id,
            authority="https://login.microsoftonline.com/consumers",
            token_cache=token_cache
        )

        accounts = app.get_accounts()
        result = None
        account_info = None
        email = None

        if accounts:
            self._login_log_callback("尝试使用缓存账户静默登录...")
            account_info = accounts[0]
            result = app.acquire_token_silent(scope, account=account_info)

        if not result:
            self._login_log_callback("开始设备代码流登录...")
            flow = app.initiate_device_flow(scopes=scope)
            if "user_code" not in flow:
                self._login_log_callback("设备流初始化失败")
                return None, None, None
            self._login_callback(flow)
            result = app.acquire_token_by_device_flow(flow)
            if result and "id_token_claims" in result:
                email = result["id_token_claims"].get("preferred_username") or result["id_token_claims"].get("email")

        if "access_token" in result:
            self._login_log_callback("微软令牌获取成功")
            self._save_token_cache(token_cache)
            account_id = account_info.get("home_account_id") if account_info else None
            return result["access_token"], account_id, email
        else:
            self._login_log_callback(f"认证失败: {result.get('error')} - {result.get('error_description')}")
            return None, None, None

    def _get_xbox_tokens(self, ms_token: str) -> Tuple[Optional[str], Optional[str]]:
        """Xbox 认证链，返回 (xsts_token, user_hash)"""
        # Xbox Live 令牌
        live_url = "https://user.auth.xboxlive.com/user/authenticate"
        live_payload = {
            "Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": f"d={ms_token}"},
            "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"
        }
        headers = {"Content-Type": "application/json"}

        try:
            resp = requests.post(live_url, json=live_payload, headers=headers)
            if resp.status_code != 200:
                self._login_log_callback(f"Xbox Live 令牌失败: {resp.status_code}")
                return None, None
            data = resp.json()
            xbl_token = data["Token"]
            user_hash = data["DisplayClaims"]["xui"][0]["uhs"]

            # XSTS 令牌
            xsts_url = "https://xsts.auth.xboxlive.com/xsts/authorize"
            xsts_payload = {
                "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbl_token]},
                "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"
            }
            resp = requests.post(xsts_url, json=xsts_payload, headers=headers)
            if resp.status_code != 200:
                self._login_log_callback(f"XSTS 令牌失败: {resp.status_code}")
                return None, None
            xsts_token = resp.json()["Token"]
            return xsts_token, user_hash
        except Exception as e:
            self._login_log_callback(f"Xbox 认证异常: {e}")
            return None, None

    def _get_minecraft_token(self, xsts_token: str, user_hash: str) -> Optional[str]:
        """获取 Minecraft 访问令牌"""
        url = "https://api.minecraftservices.com/authentication/login_with_xbox"
        payload = {"identityToken": f"XBL3.0 x={user_hash};{xsts_token}"}
        try:
            resp = requests.post(url, json=payload, headers={"Content-Type": "application/json"})
            if resp.status_code != 200:
                self._login_log_callback(f"Minecraft 令牌失败: {resp.status_code}")
                return None
            return resp.json()["access_token"]
        except Exception as e:
            self._login_log_callback(f"Minecraft 令牌异常: {e}")
            return None

    def _check_ownership(self, mc_token: str) -> Tuple[bool, Optional[dict], Optional[str]]:
        """验证 Minecraft 所有权，返回 (是否拥有, profile, skin_url)"""
        url = "https://api.minecraftservices.com/minecraft/profile"
        headers = {"Authorization": f"Bearer {mc_token}"}
        try:
            resp = requests.get(url, headers=headers)
            if resp.status_code == 200:
                profile = resp.json()
                skin_url = profile.get("skins", [{}])[0].get("url", "")
                self._login_log_callback(f"玩家: {profile['name']} (UUID: {profile['id']})")
                return True, profile, skin_url
            elif resp.status_code == 404:
                self._login_log_callback("账户未购买 Minecraft Java 版")
                return False, None, None
            else:
                self._login_log_callback(f"所有权检查失败: {resp.status_code}")
                return False, None, None
        except Exception as e:
            self._login_log_callback(f"所有权检查异常: {e}")
            return False, None, None

    # ==================== 皮肤管理 ====================
    def _get_skin_path(self, account: MinecraftAccount) -> Path:
        skin_dir = self.data_dir / "skins"
        skin_dir.mkdir(exist_ok=True)
        return skin_dir / f"{account.account_id}.png"

    def download_skin(self, account_alias: str, force_refresh: bool = False) -> Optional[Path]:
        """下载账户皮肤，返回本地路径"""
        account = next((acc for acc in self.accounts.values() if acc.alias == account_alias), None)
        if not account:
            self._log(f"账户不存在: {account_alias}")
            return None

        cache_path = self._get_skin_path(account)
        if not force_refresh and cache_path.exists():
            return cache_path

        if not account.skin_url:
            # 尝试刷新档案
            if not self.refresh_account_profile(account_alias):
                return None
            account = self.accounts[account.account_id]
            if not account.skin_url:
                self._log("无法获取皮肤 URL")
                return None

        try:
            resp = requests.get(account.skin_url, stream=True)
            if resp.status_code == 200:
                with open(cache_path, 'wb') as f:
                    for chunk in resp.iter_content(1024):
                        f.write(chunk)
                account.skin_cache_path = str(cache_path)
                self._save_accounts()
                return cache_path
            else:
                self._log(f"皮肤下载失败: HTTP {resp.status_code}")
                return None
        except Exception as e:
            self._log(f"皮肤下载异常: {e}")
            return None

    def refresh_skin(self, account_alias: str) -> Optional[Path]:
        return self.download_skin(account_alias, force_refresh=True)

    # ==================== 公共接口 ====================
    def add_account(self) -> bool:
        """添加新账户（交互式）"""
        cache_file = f"account_{uuid.uuid4().hex[:8]}"

        ms_token, account_id, email = self._get_microsoft_token(cache_file)
        if not ms_token:
            return False

        xsts_token, user_hash = self._get_xbox_tokens(ms_token)
        if not xsts_token:
            return False

        mc_token = self._get_minecraft_token(xsts_token, user_hash)
        if not mc_token:
            return False

        has_mc, profile, skin_url = self._check_ownership(mc_token)
        if not has_mc:
            # 删除无用缓存
            self._get_cache_path(cache_file).unlink(missing_ok=True)
            return False

        alias = profile['name']
        if not account_id:
            account_id = f"account_{len(self.accounts) + 1}"

        account = MinecraftAccount(
            alias=alias,
            account_id=account_id,
            email=email or "未知",
            profile=profile,
            cache_file=cache_file
        )
        account.skin_url = skin_url

        self.accounts[account_id] = account
        self._save_accounts()

        if len(self.accounts) == 1:
            self._set_current_account(account)

        # 自动下载皮肤
        skin_path = self.download_skin(alias, force_refresh=True)
        if skin_path:
            self._log(f"皮肤已缓存: {skin_path}")

        self._log(f"账户 '{alias}' 添加成功")
        return True

    def list_accounts(self) -> Optional[List[Tuple[str, MinecraftAccount]]]:
        if not self.accounts:
            self._log("无账户")
            return None
        return list(self.accounts.items())

    def get_current_account(self) -> Optional[MinecraftAccount]:
        return self.current_account

    def switch_account(self, account_alias: str) -> bool:
        for acc in self.accounts.values():
            if acc.alias == account_alias:
                self._set_current_account(acc)
                self._log(f"已切换到 {acc.alias}")
                return True
        self._log(f"账户 '{account_alias}' 不存在")
        return False

    def remove_account(self, account_alias: str) -> bool:
        target = None
        for aid, acc in self.accounts.items():
            if acc.alias == account_alias:
                target = (aid, acc)
                break
        if not target:
            self._log(f"账户 '{account_alias}' 不存在")
            return False

        aid, acc = target
        # 删除缓存文件
        self._get_cache_path(acc.cache_file).unlink(missing_ok=True)
        self._get_skin_path(acc).unlink(missing_ok=True)

        del self.accounts[aid]
        self._save_accounts()

        if self.current_account and self.current_account.account_id == aid:
            self.current_account = None
            self.current_account_file.unlink(missing_ok=True)

        self._log(f"账户 '{account_alias}' 已移除")
        return True

    def get_current_account_token(self) -> Optional[str]:
        """获取当前账户的 Minecraft 访问令牌（实时刷新）"""
        if not self.current_account:
            self._log("未选择账户")
            return None

        ms_token, _, _ = self._get_microsoft_token(self.current_account.cache_file)
        if not ms_token:
            return None

        xsts_token, user_hash = self._get_xbox_tokens(ms_token)
        if not xsts_token:
            return None

        mc_token = self._get_minecraft_token(xsts_token, user_hash)
        if not mc_token:
            return None

        # 验证并更新档案
        valid, profile, skin_url = self._check_ownership(mc_token)
        if not valid:
            return None

        if profile and profile['name'] != self.current_account.alias:
            self._log(f"玩家名更新: {self.current_account.alias} -> {profile['name']}")
            self.current_account.alias = profile['name']
            self.current_account.profile = profile
            self.current_account.skin_url = skin_url
            self._save_accounts()

        return mc_token

    def refresh_account_profile(self, account_alias: str) -> bool:
        """刷新账户档案（含皮肤 URL）"""
        account = next((acc for acc in self.accounts.values() if acc.alias == account_alias), None)
        if not account:
            self._log(f"账户 '{account_alias}' 不存在")
            return False

        ms_token, _, _ = self._get_microsoft_token(account.cache_file)
        if not ms_token:
            return False

        xsts_token, user_hash = self._get_xbox_tokens(ms_token)
        if not xsts_token:
            return False

        mc_token = self._get_minecraft_token(xsts_token, user_hash)
        if not mc_token:
            return False

        valid, profile, skin_url = self._check_ownership(mc_token)
        if not valid:
            return False

        old_alias = account.alias
        account.profile = profile
        account.skin_url = skin_url
        if profile['name'] != old_alias:
            account.alias = profile['name']
        self._save_accounts()

        # 刷新皮肤
        self.download_skin(account.alias, force_refresh=True)
        self._log(f"账户 '{old_alias}' 档案已更新")
        return True

    def refresh_all_account_profiles(self) -> None:
        for acc in list(self.accounts.values()):
            self.refresh_account_profile(acc.alias)

    def get_current_account_profile(self, refresh: bool = False) -> Optional[dict]:
        if not self.current_account:
            return None
        if refresh:
            self.refresh_account_profile(self.current_account.alias)
        return {
            "profile": self.current_account.profile,
            "skin_url": self.current_account.skin_url,
            "skin_cache_path": self.current_account.skin_cache_path
        }

    def get_all_accounts_profiles(self, refresh: bool = False) -> Dict[str, dict]:
        if refresh:
            self.refresh_all_account_profiles()
        return {
            acc.alias: {
                "profile": acc.profile,
                "skin_url": acc.skin_url,
                "skin_cache_path": acc.skin_cache_path
            }
            for acc in self.accounts.values()
        }


def main():
    """简单交互测试"""
    client_id = "f1709935-df0b-400c-843a-530a77fb8d3c"
    auth = MultiAccountMinecraftAuth(client_id)

    while True:
        print("\n" + "=" * 50)
        print("   Minecraft 多账户管理（简化版）")
        print("=" * 50)
        print("1. 列出账户")
        print("2. 添加账户")
        print("3. 切换账户")
        print("4. 移除账户")
        print("5. 获取当前令牌")
        print("6. 刷新当前档案")
        print("7. 下载当前皮肤")
        print("8. 退出")
        choice = input("请选择: ").strip()

        if choice == "1":
            accs = auth.list_accounts()
            if accs:
                cur = auth.get_current_account()
                for aid, acc in accs:
                    cur_mark = " [当前]" if cur and cur.account_id == aid else ""
                    print(f"{acc.alias} - {acc.email}{cur_mark}")
        elif choice == "2":
            auth.add_account()
        elif choice == "3":
            alias = input("账户别名: ").strip()
            auth.switch_account(alias)
        elif choice == "4":
            alias = input("账户别名: ").strip()
            auth.remove_account(alias)
        elif choice == "5":
            token = auth.get_current_account_token()
            if token:
                print("令牌获取成功")
            else:
                print("获取失败")
        elif choice == "6":
            if auth.current_account:
                auth.refresh_account_profile(auth.current_account.alias)
            else:
                print("无当前账户")
        elif choice == "7":
            if auth.current_account:
                path = auth.download_skin(auth.current_account.alias, force_refresh=True)
                if path:
                    print(f"皮肤已保存: {path}")
                else:
                    print("下载失败")
            else:
                print("无当前账户")
        elif choice == "8":
            break
        else:
            print("无效选择")


if __name__ == "__main__":
    main()