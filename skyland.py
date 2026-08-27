#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
森空岛自动签到 - 青龙 / Hermes 双模式
"""

import hashlib
import hmac
import json
import logging
import os
import sys
import threading
import time
from datetime import date
from urllib import parse

import requests

# ======================== 配置（环境变量） ========================
# 说明：使用更长的变量名，避免与其它脚本冲突
TOKEN_ENV = os.environ.get("SKYLAND_TOKENS", "").strip()
EXIT_WHEN_FAIL = os.environ.get("EXIT_WHEN_FAIL", "off").lower() == "on"
USE_PROXY = os.environ.get("USE_PROXY", "off").lower() == "on"
NOTIFY_TITLE = os.environ.get("NOTIFY_TITLE", "森空岛自动签到").strip()

# 运行模式：auto / qinglong / hermes
# - auto（默认）：同目录存在 notify.py（青龙面板脚本目录自带）则走青龙模式，否则走 Hermes 模式
# - hermes：日志走 stderr，通知改为输出到 stdout（Hermes 定时任务会原样投递）
# - qinglong：强制青龙模式，与旧版行为完全一致
SKYLAND_MODE = os.environ.get("SKYLAND_MODE", "auto").strip().lower()
# Hermes 模式下可选的 token 文件（每行一个 token，# 开头为注释，兼容逗号分隔）
SKYLAND_TOKEN_FILE = os.environ.get("SKYLAND_TOKEN_FILE", "").strip()
# Hermes 模式：全部签到成功时静默（stdout 不输出，定时任务不投递消息）
SKYLAND_SILENT_OK = os.environ.get("SKYLAND_SILENT_OK", "off").lower() == "on"


def _notify_py_available():
    return os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "notify.py"))


def in_hermes_mode():
    if SKYLAND_MODE == "hermes":
        return True
    if SKYLAND_MODE == "qinglong":
        return False
    return not _notify_py_available()

# ======================== 常量 ========================
APP_CODE = "4ca99fa6b56cc2ba"

LOGIN_CODE_URL = "https://as.hypergryph.com/general/v1/send_phone_code"
TOKEN_PHONE_CODE_URL = "https://as.hypergryph.com/user/auth/v2/token_by_phone_code"
TOKEN_PASSWORD_URL = "https://as.hypergryph.com/user/auth/v1/token_by_phone_password"
GRANT_CODE_URL = "https://as.hypergryph.com/user/oauth2/v2/grant"
CRED_CODE_URL = "https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code"
REFRESH_TOKEN_URL = "https://zonai.skland.com/web/v1/auth/refresh"
BINDING_URL = "https://zonai.skland.com/api/v1/game/player/binding"

SIGN_URL_MAPPING = {
    "arknights": "https://zonai.skland.com/api/v1/game/attendance",
    "endfield": "https://zonai.skland.com/web/v1/game/endfield/attendance",
}

# ======================== 日志 ========================
logger = logging.getLogger()
logger.setLevel(logging.INFO)
# Hermes 模式：日志走 stderr，stdout 只留给最终投递内容
handler = logging.StreamHandler(sys.stderr if in_hermes_mode() else sys.stdout)
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(handler)

# ======================== dId 计算（原项目） ========================
# 从 src/SecuritySm.py 复制并保持原样
import base64
import gzip
import uuid
import warnings
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers.base import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC, ECB
from cryptography.utils import CryptographyDeprecationWarning

# 原项目使用单键 TripleDES（8 字节），cryptography 新版会告警，功能不受影响，这里静默
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# 查询dId请求头
devices_info_url = "https://fp-it.portal101.cn/deviceprofile/v4"

# 数美配置
SM_CONFIG = {
    "organization": "UWXspnCCJN4sfYlNfqps",
    "appId": "default",
    "publicKey": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoinPkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sKmwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRByfRsK2gdl7llqCwIDAQAB",
    "protocol": "https",
    "apiHost": "fp-it.portal101.cn",
}

PK = serialization.load_der_public_key(base64.b64decode(SM_CONFIG["publicKey"]))

DES_RULE = {
    "appId": {"cipher": "DES", "is_encrypt": 1, "key": "uy7mzc4h", "obfuscated_name": "xx"},
    "box": {"is_encrypt": 0, "obfuscated_name": "jf"},
    "canvas": {"cipher": "DES", "is_encrypt": 1, "key": "snrn887t", "obfuscated_name": "yk"},
    "clientSize": {"cipher": "DES", "is_encrypt": 1, "key": "cpmjjgsu", "obfuscated_name": "zx"},
    "organization": {"cipher": "DES", "is_encrypt": 1, "key": "78moqjfc", "obfuscated_name": "dp"},
    "os": {"cipher": "DES", "is_encrypt": 1, "key": "je6vk6t4", "obfuscated_name": "pj"},
    "platform": {"cipher": "DES", "is_encrypt": 1, "key": "pakxhcd2", "obfuscated_name": "gm"},
    "plugins": {"cipher": "DES", "is_encrypt": 1, "key": "v51m3pzl", "obfuscated_name": "kq"},
    "pmf": {"cipher": "DES", "is_encrypt": 1, "key": "2mdeslu3", "obfuscated_name": "vw"},
    "protocol": {"is_encrypt": 0, "obfuscated_name": "protocol"},
    "referer": {"cipher": "DES", "is_encrypt": 1, "key": "y7bmrjlc", "obfuscated_name": "ab"},
    "res": {"cipher": "DES", "is_encrypt": 1, "key": "whxqm2a7", "obfuscated_name": "hf"},
    "rtype": {"cipher": "DES", "is_encrypt": 1, "key": "x8o2h2bl", "obfuscated_name": "lo"},
    "sdkver": {"cipher": "DES", "is_encrypt": 1, "key": "9q3dcxp2", "obfuscated_name": "sc"},
    "status": {"cipher": "DES", "is_encrypt": 1, "key": "2jbrxxw4", "obfuscated_name": "an"},
    "subVersion": {"cipher": "DES", "is_encrypt": 1, "key": "eo3i2puh", "obfuscated_name": "ns"},
    "svm": {"cipher": "DES", "is_encrypt": 1, "key": "fzj3kaeh", "obfuscated_name": "qr"},
    "time": {"cipher": "DES", "is_encrypt": 1, "key": "q2t3odsk", "obfuscated_name": "nb"},
    "timezone": {"cipher": "DES", "is_encrypt": 1, "key": "1uv05lj5", "obfuscated_name": "as"},
    "tn": {"cipher": "DES", "is_encrypt": 1, "key": "x9nzj1bp", "obfuscated_name": "py"},
    "trees": {"cipher": "DES", "is_encrypt": 1, "key": "acfs0xo4", "obfuscated_name": "pi"},
    "ua": {"cipher": "DES", "is_encrypt": 1, "key": "k92crp1t", "obfuscated_name": "bj"},
    "url": {"cipher": "DES", "is_encrypt": 1, "key": "y95hjkoo", "obfuscated_name": "cf"},
    "version": {"is_encrypt": 0, "obfuscated_name": "version"},
    "vpw": {"cipher": "DES", "is_encrypt": 1, "key": "r9924ab5", "obfuscated_name": "ca"},
}

BROWSER_ENV = {
    "plugins": "MicrosoftEdgePDFPluginPortableDocumentFormatinternal-pdf-viewer1,MicrosoftEdgePDFViewermhjfbmdgcfjbbpaeojofohoefgiehjai1",
    "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "canvas": "259ffe69",
    "timezone": -480,
    "platform": "Win32",
    "url": "https://www.skland.com/",
    "referer": "",
    "res": "1920_1080_24_1.25",
    "clientSize": "0_0_1080_1920_1920_1080_1920_1080",
    "status": "0011",
}


def _DES(o: dict):
    result = {}
    for i in o.keys():
        if i in DES_RULE.keys():
            rule = DES_RULE[i]
            res = o[i]
            if rule["is_encrypt"] == 1:
                c = Cipher(TripleDES(rule["key"].encode("utf-8")), ECB())
                data = str(res).encode("utf-8")
                data += b"\x00" * 8
                res = base64.b64encode(c.encryptor().update(data)).decode("utf-8")
            result[rule["obfuscated_name"]] = res
        else:
            result[i] = o[i]
    return result


def _AES(v: bytes, k: bytes):
    iv = "0102030405060708"
    key = AES(k)
    c = Cipher(key, CBC(iv.encode("utf-8")))
    c.encryptor()
    v += b"\x00"
    while len(v) % 16 != 0:
        v += b"\x00"
    return c.encryptor().update(v).hex()


def GZIP(o: dict):
    json_str = json.dumps(o, ensure_ascii=False)
    stream = gzip.compress(json_str.encode("utf-8"), 2, mtime=0)
    return base64.b64encode(stream)


def get_tn(o: dict):
    sorted_keys = sorted(o.keys())
    result_list = []
    for i in sorted_keys:
        v = o[i]
        if isinstance(v, (int, float)):
            v = str(v * 10000)
        elif isinstance(v, dict):
            v = get_tn(v)
        result_list.append(v)
    return "".join(result_list)


def get_smid():
    t = time.localtime()
    _time = "{}{:0>2d}{:0>2d}{:0>2d}{:0>2d}{:0>2d}".format(
        t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec
    )
    uid = str(uuid.uuid4())
    v = _time + hashlib.md5(uid.encode("utf-8")).hexdigest() + "00"
    smsk_web = hashlib.md5(("smsk_web_" + v).encode("utf-8")).hexdigest()[0:14]
    return v + smsk_web + "0"


def get_d_id():
    uid = str(uuid.uuid4()).encode("utf-8")
    priId = hashlib.md5(uid).hexdigest()[0:16]
    ep = PK.encrypt(uid, padding.PKCS1v15())
    ep = base64.b64encode(ep).decode("utf-8")

    browser = BROWSER_ENV.copy()
    current_time = int(time.time() * 1000)
    browser.update({"vpw": str(uuid.uuid4()), "svm": current_time, "trees": str(uuid.uuid4()), "pmf": current_time})

    des_target = {
        **browser,
        "protocol": 102,
        "organization": SM_CONFIG["organization"],
        "appId": SM_CONFIG["appId"],
        "os": "web",
        "version": "3.0.0",
        "sdkver": "3.0.0",
        "box": "",
        "rtype": "all",
        "smid": get_smid(),
        "subVersion": "1.0.0",
        "time": 0,
    }
    des_target["tn"] = hashlib.md5(get_tn(des_target).encode()).hexdigest()

    des_result = _AES(GZIP(_DES(des_target)), priId.encode("utf-8"))

    response = requests.post(
        devices_info_url,
        json={
            "appId": "default",
            "compress": 2,
            "data": des_result,
            "encode": 5,
            "ep": ep,
            "organization": SM_CONFIG["organization"],
            "os": "web",
        },
    )

    resp = response.json()
    if resp["code"] != 1100:
        raise Exception("did计算失败，请联系作者")
    return "B" + resp["detail"]["deviceId"]


# ======================== HTTP 签名 ========================
http_local = threading.local()

HEADER = {
    "cred": "",
    "User-Agent": "Mozilla/5.0 (Linux; Android 12; SM-A5560 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Safari/537.36; SKLand/1.52.1",
    "Accept-Encoding": "gzip",
    "Connection": "close",
    "X-Requested-With": "com.hypergryph.skland",
}

HEADER_LOGIN = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 12; SM-A5560 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Safari/537.36; SKLand/1.52.1",
    "Accept-Encoding": "gzip",
    "Connection": "close",
    "dId": get_d_id(),
    "X-Requested-With": "com.hypergryph.skland",
}

HEADER_FOR_SIGN = {"platform": "3", "timestamp": "", "dId": HEADER_LOGIN["dId"], "vName": "1.0.0"}


def generate_signature(path, body_or_query):
    # 同步上游 2026-05-26 修改：yj 服务器时间戳策略已调整，直接用服务器时间原值（旧版 -2 偏移已不需要）
    t = str(int(time.time()))
    token = http_local.token.encode("utf-8")
    header_ca = json.loads(json.dumps(HEADER_FOR_SIGN))
    header_ca["timestamp"] = t
    header_ca_str = json.dumps(header_ca, separators=(",", ":"))
    s = path + body_or_query + t + header_ca_str
    hex_s = hmac.new(token, s.encode("utf-8"), hashlib.sha256).hexdigest()
    md5 = hashlib.md5(hex_s.encode("utf-8")).hexdigest()
    return md5, header_ca


def get_sign_header(url: str, method, body, h):
    p = parse.urlparse(url)
    if method.lower() == "get":
        h["sign"], header_ca = generate_signature(p.path, p.query)
    else:
        h["sign"], header_ca = generate_signature(p.path, json.dumps(body) if body is not None else "")
    for i in header_ca:
        h[i] = header_ca[i]
    return h


# ======================== 业务逻辑 ========================

def parse_user_token(t):
    try:
        t = json.loads(t)
        return t["data"]["content"]
    except Exception:
        return t


def _parse_token_list(items):
    v = []
    for i in items:
        i = i.strip()
        if i and i not in v:
            v.append(parse_user_token(i))
    return v


def read_tokens():
    """读取 token：环境变量 SKYLAND_TOKENS + 可选 token 文件（SKYLAND_TOKEN_FILE）合并去重。"""
    raw = []
    if TOKEN_ENV:
        raw.extend(TOKEN_ENV.split(","))
    if SKYLAND_TOKEN_FILE:
        path = os.path.expanduser(SKYLAND_TOKEN_FILE)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    raw.extend(line.split(","))
        else:
            logger.warning(f"token 文件不存在：{path}")
    tokens = _parse_token_list(raw)
    if tokens:
        src = "环境变量 + token 文件" if (TOKEN_ENV and SKYLAND_TOKEN_FILE) else ("环境变量" if TOKEN_ENV else "token 文件")
        logger.info(f"从{src}读取到 {len(tokens)} 个 token")
    return tokens


def get_grant_code(token):
    response = requests.post(
        GRANT_CODE_URL,
        json={"appCode": APP_CODE, "token": token, "type": 0},
        headers=HEADER_LOGIN,
    )
    resp = response.json()
    if response.status_code != 200:
        raise Exception(f"获得认证代码失败：{resp}")
    if resp.get("status") != 0:
        raise Exception(f"获得认证代码失败：{resp.get('msg')}")
    return resp["data"]["code"]


def get_cred(grant):
    resp = requests.post(CRED_CODE_URL, json={"code": grant, "kind": 1}, headers=HEADER_LOGIN).json()
    if resp["code"] != 0:
        raise Exception(f"获得 cred 失败：{resp.get('message')}")
    return resp["data"]


def get_cred_by_token(token):
    return get_cred(get_grant_code(token))


def get_binding_list():
    v = []
    resp = requests.get(BINDING_URL, headers=get_sign_header(BINDING_URL, "get", None, http_local.header)).json()
    if resp["code"] != 0:
        logger.error(f"请求角色列表出现问题：{resp['message']}")
        if resp.get("message") == "用户未登录":
            return []
    for i in resp["data"]["list"]:
        if i.get("appCode") not in ("arknights", "endfield"):
            continue
        for j in i.get("bindingList"):
            j["appCode"] = i["appCode"]
        v.extend(i["bindingList"])
    return v


def sign_for_arknights(data: dict):
    body = {"gameId": data.get("gameId"), "uid": data.get("uid")}
    url = SIGN_URL_MAPPING["arknights"]
    headers = get_sign_header(url, "post", body, http_local.header)
    resp = requests.post(url, headers=headers, json=body).json()
    game_name = data.get("gameName")
    channel = data.get("channelName")
    nickname = data.get("nickName") or ""
    if resp.get("code") != 0:
        return [f"[{game_name}]角色{nickname}({channel})签到失败！原因：{resp['message']}"]
    result = ""
    for j in resp["data"]["awards"]:
        res = j["resource"]
        result += f"{res['name']}×{j.get('count') or 1}"
    return [f"[{game_name}]角色{nickname}({channel})签到成功，获得了{result}"]


def sign_for_endfield(data: dict):
    roles = data.get("roles")
    game_name = data.get("gameName")
    channel = data.get("channelName")
    result = []
    for i in roles:
        nickname = i.get("nickname") or ""
        resp = do_sign_for_endfield(i).json()
        if resp["code"] != 0:
            result.append(f"[{game_name}]角色{nickname}({channel})签到失败！原因:{resp['message']}")
        else:
            awards_result = []
            result_data = resp["data"]
            result_info_map = result_data["resourceInfoMap"]
            for a in result_data["awardIds"]:
                award_id = a["id"]
                awards = result_info_map[award_id]
                awards_result.append(f"{awards['name']}×{awards['count']}")
            result.append(f"[{game_name}]角色{nickname}({channel})签到成功，获得了:{','.join(awards_result)}")
    return result


def do_sign_for_endfield(role: dict):
    url = SIGN_URL_MAPPING["endfield"]
    headers = get_sign_header(url, "post", None, http_local.header)
    headers.update(
        {
            "Content-Type": "application/json",
            "sk-game-role": f"3_{role['roleId']}_{role['serverId']}",
            "referer": "https://game.skland.com/",
            "origin": "https://game.skland.com/",
        }
    )
    return requests.post(url, headers=headers)


def do_sign(cred_resp):
    http_local.token = cred_resp["token"]
    http_local.header = HEADER.copy()
    http_local.header["cred"] = cred_resp["cred"]

    characters = get_binding_list()
    success = True
    logs_out = []

    for i in characters:
        app_code = i["appCode"]
        if app_code == "arknights":
            msg = sign_for_arknights(i)
        elif app_code == "endfield":
            msg = sign_for_endfield(i)
        else:
            msg = [f"不支持的游戏：{app_code}"]
        logger.info(msg)
        logs_out.extend(msg)

    return success, logs_out


# ======================== 青龙通知（notify.py） ========================

def notify(title, content):
    # Hermes 模式：stdout 即定时任务投递内容（日志已走 stderr，这里只输出结果）
    if in_hermes_mode():
        if content:
            print(f"{title}\n{content}", flush=True)
        return
    # 青龙模式：调用青龙面板自带的 notify.py
    try:
        sys.path.append(os.path.dirname(__file__))
        from notify import send  # 青龙自带
        send(title, content)
    except Exception as e:
        logger.warning(f"青龙通知失败: {e}")


# ======================== 主入口 ========================

def main():
    logger.info("========== 森空岛自动签到（青龙 / Hermes 双模式） ==========")

    tokens = read_tokens()
    if not tokens:
        logger.error("SKYLAND_TOKENS 与 token 文件均为空，无法签到")
        if in_hermes_mode():
            print(
                f"{NOTIFY_TITLE} - {date.today().strftime('%Y-%m-%d')}\n未配置任何 token（SKYLAND_TOKENS 或 SKYLAND_TOKEN_FILE 为空），请检查配置",
                flush=True,
            )
        if EXIT_WHEN_FAIL:
            sys.exit(1)
        return False

    start_time = time.time()
    success = True
    all_logs = []

    for idx, token in enumerate(tokens, 1):
        logger.info(f"\n处理第 {idx}/{len(tokens)} 个账号...")
        try:
            sign_success, logs_out = do_sign(get_cred_by_token(token))
            all_logs.extend(logs_out)
            if not sign_success:
                success = False
        except Exception as ex:
            err = f"签到失败：{str(ex)}"
            logger.error(err, exc_info=ex)
            all_logs.append(err)
            success = False

    cost = (time.time() - start_time) * 1000
    logger.info(f"签到完成，耗时 {cost:.2f}ms")

    # 通知：Hermes 模式全部成功且 SKYLAND_SILENT_OK=on 时静默（stdout 为空，定时任务不投递）
    has_failure = any("失败" in line for line in all_logs)
    if in_hermes_mode() and SKYLAND_SILENT_OK and not has_failure:
        logger.info("全部签到成功，SKYLAND_SILENT_OK=on，本次静默不输出")
    else:
        notify(f"{NOTIFY_TITLE} - {date.today().strftime('%Y-%m-%d')}", "\n".join(all_logs))

    if EXIT_WHEN_FAIL and not success:
        sys.exit(1)

    return success


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
