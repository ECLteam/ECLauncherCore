from pathlib import Path
import hashlib
import zipfile
import json
import os


def replace_last(text: str, old: str, new: str) -> str:
    """
    替换字符串最后一个匹配项
    :param text: 字符串
    :param old: 需要被替换的内容
    :param new: 替换的内容
    :return: 修改后的字符串
    """
    return new.join(text.rsplit(old, 1))


def unzip(zip_path: str | Path, unzip_path: str | Path) -> bool:
    """
    解压文件
    :param zip_path: 压缩包路径
    :param unzip_path: 目标路径
    :return: bool 值, 是否完成解压
    """
    try:
        with zipfile.ZipFile(zip_path) as zip_object:
            for file in zip_object.namelist():
                zip_object.extract(file, unzip_path)
        return True
    except (zipfile.BadZipFile, FileNotFoundError):
        return False


def get_file_sha1(file_path: str | Path) -> str:
    """
    获取文件 Sha1
    :param file_path: 文件路径
    :return: Sha1 字符串
    """
    sha1 = hashlib.sha1()
    if os.path.isfile(file_path):
        with open(file_path, "rb") as open_file:
            for file_part in iter(lambda: open_file.read(8192), b""):
                sha1.update(file_part)
    return sha1.hexdigest()


def find_version(version_json: dict, game_path: Path | str, version_name: str | None = None) -> tuple[dict, Path] | None:
    """
    查找 Meta Json 的 inheritsFrom 键值对应游戏版本
    :param version_json: Meta Json 内容
    :param game_path: .minecraft 路径
    :param version_name: 这是为了适配版本合并
    :return: None 为没找到, 或对应版本 (MetaJson内容, 路径)
    """
    game_path = Path(game_path)
    if "inheritsFrom" in version_json:  # 若有Mod加载器则寻找原版游戏
        inherits_from = version_json["inheritsFrom"]
        if version_name:
            json_path = game_path / "versions" / version_name / f"{inherits_from}.json"
            if json_path.is_file():
                return json.loads(json_path.read_text("utf-8")), json_path.parent
        for version_path in (game_path / "versions").iterdir():  # 通过版本Json内的id键查找是否为对应的游戏版本, 而不是根据Json的名字判断
            if not version_path.is_dir(): continue
            game_json_path = version_path / f"{version_path.name}.json"
            if not game_json_path.is_file(): continue
            game_json = json.loads(game_json_path.read_text("utf-8"))
            if game_json["id"] != inherits_from: continue
            return game_json, version_path
        version_path = game_path / "versions" / inherits_from
        if (version_path / f"{inherits_from}.json").is_file():  # 如果没找到则尝试直接找inheritsFrom对应的版本
            return json.loads((version_path / f"{inherits_from}.json").read_text("utf-8")), version_path
        return None
    return None

