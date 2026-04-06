from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional, Dict, Tuple, Callable
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from dataclasses import dataclass
from pathlib import Path
import keyring.errors
import requests
import keyring
import base64
import msal
import uuid
import json
import os


@dataclass
class MinecraftAccount:
    """Minecraft 账户数据类"""
    alias: str
    account_id: str
    email: str
    profile: dict
    cache_file: str
    skin_url: str = ""          # 皮肤 URL
    skin_cache_path: str = ""   # 本地缓存路径

    def to_dict(self) -> dict:
        """转换为字典格式"""
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
        """从字典创建账户对象"""
        return cls(
            alias=data["alias"],
            account_id=data["account_id"],
            email=data["email"],
            profile=data["profile"],
            cache_file=data["cache_file"],
            skin_url=data.get("skin_url", ""),
            skin_cache_path=data.get("skin_cache_path", ""),
        )


class SmartKeyringManager:
    """智能密钥环管理器，自动选择可用的安全后端"""

    def __init__(self, service_name: str = "ECLAuth", log_callback: Optional[Callable[[str], None]] = None):
        self.service_name = service_name
        self.backend_type: str = "unknown"
        self.log_callback = log_callback or print
        self._setup_smart_keyring()

    def _log(self, msg: str) -> None:
        """输出日志"""
        self.log_callback(msg)

    def _setup_smart_keyring(self) -> None:
        """按优先级尝试不同的密钥环后端"""
        backends = [
            self._try_system_keyring,
            self._try_encrypted_file_keyring,
            self._try_json_file_keyring,
            self._try_custom_fallback
        ]

        for backend in backends:
            if backend():
                self._log(f"✅ 密钥环后端: {self.backend_type}")
                return

        raise RuntimeError("无法初始化任何密钥环后端")

    def _try_system_keyring(self) -> bool:
        """尝试系统原生密钥环"""
        try:
            test_key = f"test_key_{hash(self.service_name)}"
            keyring.set_password(self.service_name, test_key, "test_value")
            result = keyring.get_password(self.service_name, test_key)
            keyring.delete_password(self.service_name, test_key)

            if result == "test_value":
                self.backend_type = "system"
                self._log("当前使用安全性高的系统密钥环")
                return True
        except Exception as e:
            self._log(f"系统密钥环不可用: {e}")

        return False

    def _try_encrypted_file_keyring(self) -> bool:
        """尝试加密文件密钥环（keyrings.alt.file.EncryptedKeyring）"""
        try:
            from keyrings.alt.file import EncryptedKeyring
            keyring_obj = EncryptedKeyring()
            test_key = "test_encrypted"
            keyring_obj.set_password(self.service_name, test_key, "test")
            result = keyring_obj.get_password(self.service_name, test_key)
            keyring_obj.delete_password(self.service_name, test_key)

            if result == "test":
                keyring.set_keyring(keyring_obj)
                self.backend_type = "encrypted_file"
                self._log("当前使用安全性较高的加密文件密钥环")
                return True
        except Exception as e:
            self._log(f"加密文件密钥环失败: {e}")

        return False

    def _try_json_file_keyring(self) -> bool:
        """尝试 JSON 文件密钥环"""
        try:
            from keyrings.alt.file import JSONKeyring
            keyring_obj = JSONKeyring()
            test_key = "test_json"
            keyring_obj.set_password(self.service_name, test_key, "test")
            result = keyring_obj.get_password(self.service_name, test_key)
            keyring_obj.delete_password(self.service_name, test_key)

            if result == "test":
                keyring.set_keyring(keyring_obj)
                self.backend_type = "json_file"
                self._log("当前使用安全性良好的 JSON 密钥环")
                return True
        except Exception as e:
            self._log(f"JSON 文件密钥环失败: {e}")

        return False

    def _try_custom_fallback(self) -> bool:
        """最终回退：自定义加密文件存储"""
        try:
            class CustomFallbackKeyring:
                def __init__(self):
                    self.storage_file = os.path.expanduser("~/.ECLAuth/custom_keyring.bin")
                    os.makedirs(os.path.dirname(self.storage_file), exist_ok=True)
                    self.key = Fernet.generate_key()
                    self.fernet = Fernet(self.key)

                def set_password(self, service: str, username: str, password: str) -> None:
                    data = f"{service}|{username}|{password}"
                    encrypted = self.fernet.encrypt(data.encode())
                    with open(self.storage_file, 'ab') as f:
                        f.write(encrypted + b'\n')

                def get_password(self, service: str, username: str) -> Optional[str]:
                    try:
                        with open(self.storage_file, 'rb') as f:
                            for line in f:
                                try:
                                    decrypted = self.fernet.decrypt(line.strip()).decode()
                                    s, u, p = decrypted.split('|', 2)
                                    if s == service and u == username:
                                        return p
                                except Exception:
                                    continue
                    except FileNotFoundError:
                        pass
                    return None

            keyring.set_keyring(CustomFallbackKeyring())
            self.backend_type = "custom_fallback"
            self._log("⚠️ 使用自定义回退密钥环")
            return True

        except Exception as e:
            self._log(f"自定义回退失败: {e}")
            return False

    def get_backend_info(self) -> dict:
        """获取当前后端信息"""
        return {
            "type": self.backend_type,
            "service": self.service_name,
            "secure": self.backend_type not in ["plaintext_file", "custom_fallback"]
        }


class EncryptionManager:
    """加密管理器，负责主密码派生和敏感数据加密"""

    def __init__(self, service_name: str = "ECLAuth", log_callback: Optional[Callable[[str], None]] = None,
                 first_launch_callback: Optional[Callable[[], str]] = None):
        self.service_name = service_name
        self.data_dir = Path(os.path.expanduser("~/.ECLAuth"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.salt_file = self.data_dir / "encryption_salt.bin"

        self.log_callback = log_callback or print
        self.first_launch_callback = first_launch_callback or self._set_password
        self.keyring_manager = SmartKeyringManager(service_name, self._log)
        self.fernet: Optional[Fernet] = None
        self._ensure_encryption_key()

    def _log(self, msg: str) -> None:
        """输出日志"""
        self.log_callback(msg)

    def _set_password(self):
        while True:
            password = input("请输入主密码: ")
            confirm = input("请确认主密码: ")

            if password != confirm:
                self._log("两次输入的密码不一致，请重新输入")
                continue
            return password

    def _ensure_encryption_key(self) -> None:
        """确保加密密钥存在，若不存在则提示用户设置主密码"""
        encryption_key = keyring.get_password(self.service_name, "encryption_key")

        if encryption_key:
            self.fernet = Fernet(encryption_key.encode())
            return

        # 首次运行，设置主密码
        self._log("为了保护您的账户安全，请设置一个主密码")
        self._log(f"密钥环后端: {self.keyring_manager.backend_type}")

        while True:
            password = self.first_launch_callback()
            if len(password) < 8:
                self._log("密码长度至少8位，请重新输入")
                continue
            break

        self._generate_and_store_key(password)

    def change_password(self, new_password: str) -> Fernet:
        """
        更改主密码，生成新密钥并更新密钥环。
        返回旧的 Fernet 实例，供调用者重新加密已有数据。
        """
        if not self.fernet:
            raise RuntimeError("加密管理器未初始化，无法更改密码")

        old_fernet = self.fernet

        # 确保盐值文件存在（首次设置时应该已存在，但以防万一）
        if not self.salt_file.exists():
            salt = os.urandom(16)
            self.salt_file.write_bytes(salt)
        else:
            salt = self.salt_file.read_bytes()

        # 基于新密码和盐值派生新密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        new_key = base64.urlsafe_b64encode(kdf.derive(new_password.encode()))
        new_fernet = Fernet(new_key)

        # 更新密钥环
        keyring.set_password(self.service_name, "encryption_key", new_key.decode())

        # 更新当前实例
        self.fernet = new_fernet

        self._log("✅ 主密码已更新")
        return old_fernet

    def _generate_and_store_key(self, password: str) -> None:
        """生成加密密钥并存储到密钥环"""
        # 生成或加载盐值
        if self.salt_file.exists():
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)

        # 使用 PBKDF2 派生密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        # 存储密钥
        keyring.set_password(self.service_name, "encryption_key", key.decode())
        self.fernet = Fernet(key)

        backend_info = self.keyring_manager.get_backend_info()
        security_note = "（安全）" if backend_info["secure"] else "（注意：安全性较低）"
        self._log(f"✅ 加密设置完成 {security_note}")
        if not backend_info["secure"]:
            self._log("⚠️  当前使用安全性较低的后端，建议在桌面环境中运行以获得更好的安全性")

    def encrypt_data(self, data: str) -> str:
        """加密字符串数据"""
        if not self.fernet:
            raise RuntimeError("加密管理器未正确初始化")
        encrypted = self.fernet.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt_data(self, encrypted_data: str) -> str:
        """解密字符串数据"""
        if not self.fernet:
            raise RuntimeError("加密管理器未正确初始化")
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"解密失败: {e}") from e


class MultiAccountMinecraftAuth:
    """Minecraft 多账户认证管理器（带加密存储，支持回调日志）"""

    def __init__(self, client_id: str, data_dir: str = "~/.ECLAuth"):
        self.client_id = client_id
        self.data_dir = Path(os.path.expanduser(data_dir))
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # 日志回调（默认使用 print）
        self._log_callback: Callable[[str], None] = print
        self._login_log_callback: Callable[[str], None] = print
        self._login_callback: Callable[[dict], None] = self._login_print
        self._first_launch_callback: Optional[Callable[[], str]] = None

        # 加密管理器（延迟初始化）
        self.encryption: Optional[EncryptionManager] = None

        # 账户相关属性
        self.accounts: Dict[str, MinecraftAccount] = {}
        self.current_account: Optional[MinecraftAccount] = None
        self.accounts_file = self.data_dir / "accounts.json"
        self.current_account_file = self.data_dir / "current_account.txt"

        # 初始化标志
        self._initialized = False

    # ==================== 日志回调设置 ====================
    def set_output_log(self, func: Callable[[str], None]) -> None:
        """设置日志输出回调函数"""
        self._log_callback = func

    def set_output_login_log(self, func: Callable[[str], None]) -> None:
        """设置登录日志输出回调函数"""
        self._login_log_callback = func

    def set_login_callback(self, func: Callable[[dict], None]) -> None:
        """登录回调函数"""
        self._login_callback = func

    def set_first_launch_callback(self, func: Callable[[], str]) -> None:
        """首次启动回调函数"""
        self._first_launch_callback = func

    def _log(self, msg: str) -> None:
        """内部日志输出"""
        self._log_callback(msg)

    @staticmethod
    def _login_print(flow: dict):
        print(flow)
        print(f"请在浏览器访问：{flow['verification_uri']}，并在其中输入：{flow['user_code']}")

    # ==================== 手动初始化 ====================
    def initialize(self) -> bool:
        """手动初始化，创建加密管理器并加载账户数据。必须在使用其他功能前调用。"""
        if self._initialized:
            self._log("⚠️ 已经初始化过，跳过")
            return True

        try:
            # 创建加密管理器（此时会询问主密码如果首次）
            self.encryption = EncryptionManager(log_callback=self._log_callback, first_launch_callback=self._first_launch_callback)
            # 加载账户数据
            self._load_accounts()
            self._initialized = True
            self._log("✅ 初始化成功")
            return True
        except Exception as e:
            self._log(f"❌ 初始化失败: {e}")
            return False

    def _ensure_initialized(self) -> None:
        """确保已初始化，否则抛出异常"""
        if not self._initialized:
            raise RuntimeError("请先调用 initialize() 方法进行初始化")

    # ==================== 内部加载/保存方法 ====================
    def _load_accounts(self) -> None:
        """加载已保存的账户（自动解密）"""
        if not self.accounts_file.exists():
            return

        try:
            with open(self.accounts_file, 'r') as f:
                accounts_data = json.load(f)
                for account_id, enc_data in accounts_data.items():
                    # 解密账户数据
                    if isinstance(enc_data, str):
                        decrypted_data = self.encryption.decrypt_data(enc_data)
                        account_dict = json.loads(decrypted_data)
                        self.accounts[account_id] = MinecraftAccount.from_dict(account_dict)
            self._log(f"已加载 {len(self.accounts)} 个账户")
        except Exception as e:
            self._log(f"加载账户数据失败: {e}")

        # 加载当前账户
        if self.current_account_file.exists():
            try:
                with open(self.current_account_file, 'r') as f:
                    current_id = f.read().strip()
                    if current_id in self.accounts:
                        self.current_account = self.accounts[current_id]
                        self._log(f"当前选中账户: {self.current_account.alias}")
            except Exception as e:
                self._log(f"加载当前账户失败: {e}")

    def _save_accounts(self) -> None:
        """保存所有账户（加密存储）"""
        accounts_data = {}
        for account_id, account in self.accounts.items():
            encrypted = self.encryption.encrypt_data(json.dumps(account.to_dict()))
            accounts_data[account_id] = encrypted

        try:
            with open(self.accounts_file, 'w') as f:
                json.dump(accounts_data, f, indent=2)
        except Exception as e:
            self._log(f"保存账户数据失败: {e}")

    def _set_current_account(self, account: MinecraftAccount) -> None:
        """设置当前活动账户"""
        self.current_account = account
        try:
            with open(self.current_account_file, 'w') as f:
                f.write(account.account_id)
        except Exception as e:
            self._log(f"保存当前账户设置失败: {e}")

    # ==================== 令牌缓存加密 ====================
    def _build_persistence_cache(self, cache_file: str) -> msal.SerializableTokenCache:
        """创建并加载加密的令牌缓存"""
        cache_path = self.data_dir / "cache" / f"{cache_file}.bin"
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        token_cache = msal.SerializableTokenCache()

        if cache_path.exists():
            try:
                with open(cache_path, 'r') as f:
                    encrypted = f.read()
                    decrypted = self.encryption.decrypt_data(encrypted)
                    token_cache.deserialize(decrypted)
            except Exception as e:
                self._log(f"加载加密缓存失败: {e}")

        # 保存路径以便后续保存
        token_cache.cache_path = str(cache_path)
        return token_cache

    def _save_cache(self, token_cache: msal.SerializableTokenCache) -> None:
        """保存加密的令牌缓存"""
        if not hasattr(token_cache, 'cache_path') or not token_cache.cache_path:
            return
        try:
            cache_data = token_cache.serialize()
            encrypted = self.encryption.encrypt_data(cache_data)
            with open(token_cache.cache_path, 'w') as f:
                f.write(encrypted)
        except Exception as e:
            self._log(f"保存加密缓存失败: {e}")

    # ==================== 认证链方法 ====================
    def _get_microsoft_token(self, cache_file: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        获取微软访问令牌
        返回: (access_token, account_id, email)
        """
        scope = ["XboxLive.signin"]

        token_cache = self._build_persistence_cache(cache_file)
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
            self._login_log_callback("检测到已缓存的账户，尝试静默获取令牌...")
            account_info = accounts[0]
            result = app.acquire_token_silent(scopes=scope, account=account_info)

        if not result:
            self._login_log_callback("未找到有效缓存或静默获取失败，开始设备代码流登录...")
            try:
                flow = app.initiate_device_flow(scopes=scope)
                if "user_code" not in flow:
                    raise ValueError("未能创建设备流: " + json.dumps(flow, indent=2))

                self._login_callback(flow)
                result = app.acquire_token_by_device_flow(flow)

                if result and "id_token_claims" in result:
                    id_claims = result["id_token_claims"]
                    email = id_claims.get("preferred_username") or id_claims.get("email")
            except Exception as e:
                self._login_log_callback(f"设备代码流失败: {e}")
                return None, None, None

        if "access_token" in result:
            self._login_log_callback("微软访问令牌获取成功！")
            self._save_cache(token_cache)
            account_id = account_info.get("home_account_id") if account_info else None
            return result["access_token"], account_id, email
        else:
            self._login_log_callback(f"认证失败：{result.get('error')}: {result.get('error_description')}")
            return None, None, None

    def _get_xbox_chain_tokens(self, msft_access_token: str) -> Tuple[Optional[str], Optional[str]]:
        """
        通过 Xbox 认证链获取 XSTS 令牌
        返回: (xsts_token, user_hash)
        """
        # 获取 Xbox Live 令牌
        xbox_live_url = "https://user.auth.xboxlive.com/user/authenticate"
        xbox_live_payload = {
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": f"d={msft_access_token}"
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        try:
            resp = requests.post(xbox_live_url, json=xbox_live_payload, headers=headers)
            if resp.status_code != 200:
                self._login_log_callback(f"获取 Xbox Live 令牌失败: {resp.status_code} - {resp.text}")
                return None, None

            xbox_live_data = resp.json()
            xbox_live_token = xbox_live_data["Token"]
            user_hash = xbox_live_data["DisplayClaims"]["xui"][0]["uhs"]
            self._login_log_callback("Xbox Live 令牌获取成功。")

            # 获取 XSTS 令牌
            xsts_url = "https://xsts.auth.xboxlive.com/xsts/authorize"
            xsts_payload = {
                "Properties": {
                    "SandboxId": "RETAIL",
                    "UserTokens": [xbox_live_token]
                },
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT"
            }

            resp = requests.post(xsts_url, json=xsts_payload, headers=headers)
            if resp.status_code != 200:
                self._login_log_callback(f"获取 XSTS 令牌失败: {resp.status_code} - {resp.text}")
                return None, None

            xsts_data = resp.json()
            xsts_token = xsts_data["Token"]
            self._login_log_callback("XSTS 令牌获取成功。")

            return xsts_token, user_hash

        except Exception as e:
            self._login_log_callback(f"Xbox 认证链失败: {e}")
            return None, None

    def _get_minecraft_token(self, xsts_token: str, user_hash: str) -> Optional[str]:
        """使用 Xbox 令牌获取 Minecraft 访问令牌"""
        mc_auth_url = "https://api.minecraftservices.com/authentication/login_with_xbox"
        mc_auth_payload = {
            "identityToken": f"XBL3.0 x={user_hash};{xsts_token}"
        }
        headers = {"Content-Type": "application/json"}

        try:
            resp = requests.post(mc_auth_url, json=mc_auth_payload, headers=headers)
            if resp.status_code != 200:
                self._login_log_callback(f"获取 Minecraft 令牌失败: {resp.status_code} - {resp.text}")
                return None
            mc_data = resp.json()
            mc_access_token = mc_data["access_token"]
            self._login_log_callback("Minecraft 访问令牌获取成功！")
            return mc_access_token
        except Exception as e:
            self._login_log_callback(f"获取 Minecraft 令牌失败: {e}")
            return None

    def _check_minecraft_ownership(self, mc_access_token: str) -> Tuple[bool, Optional[dict], Optional[str]]:
        """验证 Minecraft 所有权并获取玩家档案和皮肤 URL"""
        profile_url = "https://api.minecraftservices.com/minecraft/profile"
        headers = {"Authorization": f"Bearer {mc_access_token}"}

        try:
            resp = requests.get(profile_url, headers=headers)

            if resp.status_code == 200:
                profile = resp.json()
                # 解析皮肤 URL
                skin_url = ""
                if "skins" in profile and profile["skins"]:
                    skin_url = profile["skins"][0].get("url", "")
                self._login_log_callback(f"🎉 Minecraft 所有权验证成功！")
                self._login_log_callback(f"   玩家名称: {profile['name']}")
                self._login_log_callback(f"   玩家 UUID: {profile['id']}")
                if skin_url:
                    self._login_log_callback(f"   皮肤 URL: {skin_url}")
                return True, profile, skin_url
            elif resp.status_code == 404:
                self._login_log_callback("❌ 该账户未购买 Minecraft Java 版")
                return False, None, None
            else:
                self._login_log_callback(f"⚠️ 检查 Minecraft 所有权时出错: {resp.status_code} - {resp.text}")
                return False, None, None
        except Exception as e:
            self._login_log_callback(f"检查 Minecraft 所有权失败: {e}")
            return False, None, None

    # ==================== 皮肤缓存方法 ====================
    def _get_skin_cache_path(self, account: MinecraftAccount) -> Path:
        """生成皮肤缓存文件路径（明文 PNG）"""
        skin_dir = self.data_dir / "skins"
        skin_dir.mkdir(exist_ok=True)
        # 使用 account_id 作为文件名，确保唯一性
        return skin_dir / f"{account.account_id}.png"

    def download_skin(self, account_alias: str, force_refresh: bool = False) -> Optional[Path]:
        """下载并缓存指定账户的皮肤，返回本地路径（明文 PNG）"""
        self._ensure_initialized()
        account = None
        for acc in self.accounts.values():
            if acc.alias == account_alias:
                account = acc
                break
        if not account:
            self._log(f"❌ 未找到账户: {account_alias}")
            return None

        cache_path = self._get_skin_cache_path(account)
        if not force_refresh and cache_path.exists():
            self._log(f"✅ 皮肤已缓存: {cache_path}")
            return cache_path

        if not account.skin_url:
            # 如果没有保存 skin_url，尝试刷新账户档案以获取最新皮肤 URL
            self._log("账户未保存皮肤 URL，尝试刷新档案...")
            if not self.refresh_account_profile(account_alias):
                return None
            # 刷新后重新获取 account 对象
            account = self.accounts.get(account.account_id)
            if not account or not account.skin_url:
                self._log("❌ 无法获取皮肤 URL")
                return None

        # 下载皮肤
        try:
            resp = requests.get(account.skin_url, stream=True)
            if resp.status_code == 200:
                with open(cache_path, 'wb') as f:
                    for chunk in resp.iter_content(1024):
                        f.write(chunk)
                self._log(f"✅ 皮肤已下载: {cache_path}")
                # 更新缓存路径到 account 对象
                account.skin_cache_path = str(cache_path)
                self._save_accounts()
                return cache_path
            else:
                self._log(f"❌ 下载皮肤失败: HTTP {resp.status_code}")
                return None
        except Exception as e:
            self._log(f"❌ 下载皮肤异常: {e}")
            return None

    def refresh_skin(self, account_alias: str) -> Optional[Path]:
        """强制刷新指定账户的皮肤（重新下载）"""
        return self.download_skin(account_alias, force_refresh=True)

    # ==================== 公共接口方法 ====================
    def add_account(self) -> bool:
        """添加新账户（交互式）"""
        self._ensure_initialized()

        cache_file = f"account_{uuid.uuid4().hex[:8]}"

        # 1. 微软登录
        ms_token, account_id, email = self._get_microsoft_token(cache_file)
        if not ms_token:
            return False

        # 2. Xbox 认证链
        xsts_token, user_hash = self._get_xbox_chain_tokens(ms_token)
        if not xsts_token:
            return False

        # 3. Minecraft 令牌
        mc_token = self._get_minecraft_token(xsts_token, user_hash)
        if not mc_token:
            return False

        # 4. 验证所有权并获取档案和皮肤 URL
        has_minecraft, profile, skin_url = self._check_minecraft_ownership(mc_token)
        if not has_minecraft:
            # 移除临时缓存
            cache_path = self.data_dir / "cache" / f"{cache_file}.bin"
            if cache_path.exists():
                cache_path.unlink()
            return False

        # 5. 保存账户
        alias = profile['name']
        if not account_id:
            account_id = f"account_{len(self.accounts) + 1}"

        account = MinecraftAccount(
            alias=alias,
            account_id=account_id,
            email=email or "未知",
            profile=profile,
            cache_file=cache_file,
            skin_url=skin_url,
            skin_cache_path=""  # 稍后下载皮肤时再填充
        )

        self.accounts[account_id] = account
        self._save_accounts()

        if len(self.accounts) == 1:
            self._set_current_account(account)

        self._log(f"✅ 账户 '{alias}' 添加成功！")
        # 可选：自动下载皮肤
        # self.download_skin(alias)
        return True

    def list_accounts(self) -> list | None:
        """列出所有已保存的账户"""
        self._ensure_initialized()

        if not self.accounts:
            self._log("暂无已保存的账户")
            return None

        return list(self.accounts.items())

    def get_current_account(self) -> MinecraftAccount:
        return self.current_account

    def switch_account(self, account_alias: str) -> bool:
        """切换到指定别名的账户"""
        self._ensure_initialized()

        for account in self.accounts.values():
            if account.alias == account_alias:
                self._set_current_account(account)
                self._log(f"✅ 已切换到账户: {account.alias}")
                return True

        self._log(f"❌ 未找到账户: {account_alias}")
        return False

    def remove_account(self, account_alias: str) -> bool:
        """移除指定别名的账户"""
        self._ensure_initialized()

        target_id = None
        target_account = None

        for aid, acc in self.accounts.items():
            if acc.alias == account_alias:
                target_id = aid
                target_account = acc
                break

        if not target_account:
            self._log(f"❌ 未找到账户: {account_alias}")
            return False

        # 删除缓存文件（令牌缓存和皮肤缓存）
        cache_path = self.data_dir / "cache" / f"{target_account.cache_file}.bin"
        if cache_path.exists():
            cache_path.unlink()
        skin_path = self._get_skin_cache_path(target_account)
        if skin_path.exists():
            skin_path.unlink()

        del self.accounts[target_id]
        self._save_accounts()

        if self.current_account and self.current_account.account_id == target_id:
            self.current_account = None
            if self.current_account_file.exists():
                self.current_account_file.unlink()

        self._log(f"✅ 账户 '{account_alias}' 已移除")
        return True

    def get_current_account_token(self) -> Optional[str]:
        """获取当前账户的 Minecraft 访问令牌（实时刷新）"""
        self._ensure_initialized()

        if not self.current_account:
            self._log("❌ 未选择任何账户")
            return None

        self._log(f"正在为账户 {self.current_account.alias} 获取 Minecraft 令牌...")

        # 重新获取完整令牌链
        ms_token, _, _ = self._get_microsoft_token(self.current_account.cache_file)
        if not ms_token:
            self._login_log_callback("❌ 获取微软令牌失败")
            return None

        xsts_token, user_hash = self._get_xbox_chain_tokens(ms_token)
        if not xsts_token:
            self._login_log_callback("❌ Xbox 认证链失败")
            return None

        mc_token = self._get_minecraft_token(xsts_token, user_hash)
        if not mc_token:
            self._login_log_callback("❌ 获取 Minecraft 令牌失败")
            return None

        # 验证并更新档案
        is_valid, profile, skin_url = self._check_minecraft_ownership(mc_token)
        if not is_valid:
            self._login_log_callback("❌ Minecraft 令牌验证失败")
            return None

        # 如果玩家名变化，更新别名
        if profile and profile['name'] != self.current_account.alias:
            self._log(f"检测到玩家 ID 变化: {self.current_account.alias} -> {profile['name']}")
            self.current_account.alias = profile['name']
            self.current_account.profile = profile
            self.current_account.skin_url = skin_url
            self._save_accounts()

        return mc_token

    def refresh_account_profile(self, account_alias: str) -> bool:
        """刷新指定账户的档案信息（包括皮肤 URL）"""
        self._ensure_initialized()

        for account in self.accounts.values():
            if account.alias != account_alias:
                continue

            self._log(f"刷新账户档案: {account.alias}")

            ms_token, _, _ = self._get_microsoft_token(account.cache_file)
            if not ms_token:
                self._login_log_callback("❌ 获取微软令牌失败")
                return False

            xsts_token, user_hash = self._get_xbox_chain_tokens(ms_token)
            if not xsts_token:
                return False

            mc_token = self._get_minecraft_token(xsts_token, user_hash)
            if not mc_token:
                return False

            is_valid, profile, skin_url = self._check_minecraft_ownership(mc_token)
            if not is_valid:
                return False

            old_alias = account.alias
            account.profile = profile
            account.skin_url = skin_url
            if profile['name'] != old_alias:
                self._log(f"更新账户别名: {old_alias} -> {profile['name']}")
                account.alias = profile['name']

            self._save_accounts()
            self._log(f"✅ {old_alias} 档案已更新")
            return True

        self._log(f"❌ 未找到账户: {account_alias}")
        return False

    def refresh_all_account_profiles(self) -> None:
        """刷新所有账户的档案信息"""
        self._ensure_initialized()

        updated = 0

        for account in list(self.accounts.values()):
            self._log(f"刷新账户档案: {account.alias}")
            if self.refresh_account_profile(account.alias):
                updated += 1
            else:
                self._log(f"  ❌ {account.alias} 档案刷新失败")

        self._log(f"档案刷新完成，成功更新 {updated}/{len(self.accounts)} 个账户")

    def change_master_password(self, new_password: str) -> bool:
        """更改主密码（重新加密所有数据）"""
        if len(new_password) < 8:
            self._log("密码长度至少8位")
            return False

        self._ensure_initialized()

        # 获取旧 Fernet（用于解密）
        old_fernet = self.encryption.fernet

        # 更改密码（生成新密钥并更新加密管理器）
        try:
            new_fernet = self.encryption.change_password(new_password)
        except Exception as e:
            self._log(f"更改密码失败: {e}")
            return False

        self._log("重新加密缓存文件...")
        success = 0
        total = len(self.accounts)

        # 重新加密每个账户的缓存文件
        for account in self.accounts.values():
            cache_path = self.data_dir / "cache" / f"{account.cache_file}.bin"
            if cache_path.exists():
                try:
                    with open(cache_path, 'r') as f:
                        encrypted_data = f.read()
                    # 用旧密钥解密
                    decrypted_bytes = old_fernet.decrypt(base64.urlsafe_b64decode(encrypted_data.encode()))
                    decrypted_data = decrypted_bytes.decode()
                    # 用新密钥加密
                    new_encrypted = new_fernet.encrypt(decrypted_data.encode())
                    new_encrypted_b64 = base64.urlsafe_b64encode(new_encrypted).decode()
                    with open(cache_path, 'w') as f:
                        f.write(new_encrypted_b64)
                    success += 1
                except Exception as e:
                    self._log(f"重新加密账户 {account.alias} 的缓存失败: {e}")

        # 重新加密账户文件（通过 _save_accounts 会自动使用新密钥）
        self._save_accounts()

        self._log(f"✅ 主密码更改完成，成功重新加密 {success}/{total} 个账户")
        return True

    # ==================== 获取档案信息 ====================
    def get_current_account_profile(self, refresh: bool = False) -> Optional[dict]:
        """获取当前账户的档案信息

        Args:
            refresh: 是否实时刷新（重新认证）获取最新档案，默认为 False

        Returns:
            档案字典，包含 name, id 等字段，如果无当前账户则返回 None
        """
        self._ensure_initialized()

        if not self.current_account:
            self._log("❌ 未选择任何账户")
            return None

        if refresh:
            # 刷新档案（重新认证）
            if self.refresh_account_profile(self.current_account.alias):
                return self.current_account.profile
            else:
                return None
        else:
            return self.current_account.profile

    def get_all_accounts_profiles(self, refresh: bool = False) -> Dict[str, dict]:
        """获取所有账户的档案信息

        Args:
            refresh: 是否实时刷新（重新认证）获取最新档案，默认为 False

        Returns:
            字典，键为账户别名，值为档案字典
        """
        self._ensure_initialized()

        profiles = {}
        if refresh:
            # 逐个刷新所有账户档案
            self.refresh_all_account_profiles()

        for alias, account in self.accounts.items():
            profiles[alias] = account.profile
        return profiles


def main() -> None:
    """主菜单循环"""
    client_id = "f1709935-df0b-400c-843a-530a77fb8d3c"
    auth = MultiAccountMinecraftAuth(client_id)

    # 可以自定义日志回调（这里使用默认print）
    # auth.set_output_log(print)

    # 手动初始化
    if not auth.initialize():
        print("初始化失败，退出")
        return

    while True:
        print("\n" + "=" * 50)
        print("        Minecraft 多账户登录管理系统（加密版）")
        print("=" * 50)
        print("1. 列出所有账户")
        print("2. 添加新账户")
        print("3. 切换账户")
        print("4. 移除账户")
        print("5. 获取当前账户令牌")
        print("6. 刷新所有账户档案")
        print("7. 刷新指定账户档案")
        print("8. 更改主密码")
        print("9. 获取当前账户档案")
        print("10. 获取所有账户档案")
        print("11. 下载当前账户皮肤")
        print("12. 刷新当前账户皮肤")
        print("13. 退出")

        choice = input("\n请选择操作 (1-13): ").strip()

        def list_accounts():
            accounts_list = auth.list_accounts()
            if accounts_list:
                current_account = auth.get_current_account()
                for i, (account_id, account) in enumerate(accounts_list, 1):
                    current = " [当前]" if current_account and account_id == current_account.account_id else ""
                    print(f"{i}. {account.alias} - {account.email}{current}")

        if choice == "1":
            list_accounts()
        elif choice == "2":
            if auth.add_account():
                print("✅ 账户添加成功！")
            else:
                print("❌ 账户添加失败")
        elif choice == "3":
            list_accounts()
            if auth.accounts:
                alias = input("请输入要切换的账户别名: ").strip()
                auth.switch_account(alias)
        elif choice == "4":
            list_accounts()
            if auth.accounts:
                alias = input("请输入要移除的账户别名: ").strip()
                auth.remove_account(alias)
        elif choice == "5":
            token = auth.get_current_account_token()
            if token:
                print(f"\n🎮 Minecraft 令牌获取成功！")
                if auth.current_account:
                    p = auth.current_account.profile
                    print(f"玩家: {p['name']} (UUID: {p['id']})")
            else:
                print("❌ 获取 Minecraft 令牌失败")
        elif choice == "6":
            auth.refresh_all_account_profiles()
        elif choice == "7":
            list_accounts()
            if auth.accounts:
                alias = input("请输入要刷新档案的账户别名: ").strip()
                auth.refresh_account_profile(alias)
        elif choice == "8":
            # 获取新密码
            while True:
                new_password = input("请输入新主密码: ")
                confirm = input("请确认新主密码: ")

                if new_password != confirm:
                    print("两次输入的密码不一致，请重新输入")
                    continue
                if len(new_password) < 8:
                    print("密码长度至少8位，请重新输入")
                    continue
                break
            auth.change_master_password(new_password)
        elif choice == "9":
            profile = auth.get_current_account_profile(refresh=False)
            if profile:
                print(f"\n📄 当前账户档案:")
                print(f"   玩家名称: {profile['name']}")
                print(f"   玩家 UUID: {profile['id']}")
            else:
                print("❌ 当前无账户或获取失败")
        elif choice == "10":
            profiles = auth.get_all_accounts_profiles(refresh=False)
            if profiles:
                print("\n📄 所有账户档案:")
                for alias, prof in profiles.items():
                    print(f"   {alias}: {prof['name']} (UUID: {prof['id']})")
            else:
                print("❌ 无已保存的账户")
        elif choice == "11":
            if auth.current_account:
                path = auth.download_skin(auth.current_account.alias, force_refresh=False)
                if path:
                    print(f"✅ 皮肤已保存至: {path}")
                else:
                    print("❌ 皮肤下载失败")
            else:
                print("❌ 未选择任何账户")
        elif choice == "12":
            if auth.current_account:
                path = auth.refresh_skin(auth.current_account.alias)
                if path:
                    print(f"✅ 皮肤已刷新并保存至: {path}")
                else:
                    print("❌ 皮肤刷新失败")
            else:
                print("❌ 未选择任何账户")
        elif choice == "13":
            print("再见！")
            break
        else:
            print("❌ 无效选择，请重新输入")


if __name__ == "__main__":
    main()