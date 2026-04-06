import requests


def upload_mclo_gs(log_content: str, meta_data: list[dict[str, str | int | bool]] | None = None):
    json_data = {
        "content": log_content,
        "source": "EuoraCraftLauncher",
        "metadata": meta_data or []
    }
    return requests.post("https://api.mclo.gs/1/log", json=json_data).json()


def upload_of_crash_analyze(all_log: dict[str, str]):
    all_info = {}
    for log_name, log_content in all_log.items():
        if not log_content: continue
        all_info.update({
            log_name: upload_mclo_gs(log_content)
        })
    return all_info