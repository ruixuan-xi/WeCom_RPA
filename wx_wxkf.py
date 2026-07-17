import logging
import os
import threading
import xml.etree.ElementTree as ET
from pathlib import Path

import requests
from flask import Flask, abort, request

from WXBizMsgCrypt import WXBizMsgCrypt
from config import env_bool, required_env

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

WECOM_TOKEN = required_env("WECOM_TOKEN")
WECOM_ENCODING_AES_KEY = required_env("WECOM_ENCODING_AES_KEY")
WECOM_CORP_ID = required_env("WECOM_CORP_ID")
WECOM_SECRET = required_env("WECOM_KF_SECRET")
WECOM_OPEN_KFID = required_env("WECOM_OPEN_KFID")
RPA_KF_WEBHOOK_URL = required_env("RPA_KF_WEBHOOK_URL")
CURSOR_FILE = Path(os.getenv("KF_CURSOR_FILE", "kf_cursor.txt"))

wxcpt = WXBizMsgCrypt(WECOM_TOKEN, WECOM_ENCODING_AES_KEY, WECOM_CORP_ID)
cursor_lock = threading.Lock()


def read_cursor():
    try:
        return CURSOR_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return ""


def save_cursor(cursor):
    CURSOR_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_file = CURSOR_FILE.with_suffix(CURSOR_FILE.suffix + ".tmp")
    temp_file.write_text(cursor, encoding="utf-8")
    temp_file.replace(CURSOR_FILE)


def get_access_token():
    response = requests.get(
        "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
        params={"corpid": WECOM_CORP_ID, "corpsecret": WECOM_SECRET},
        timeout=10,
    )
    response.raise_for_status()
    result = response.json()
    if result.get("errcode") != 0:
        raise RuntimeError(f"Failed to obtain access token: errcode={result.get('errcode')}")
    return result["access_token"]


def sync_kf_messages(access_token, message_token, cursor):
    response = requests.post(
        "https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg",
        params={"access_token": access_token},
        json={
            "token": message_token,
            "cursor": cursor,
            "limit": 1000,
            "voice_format": 0,
            "open_kfid": WECOM_OPEN_KFID,
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def send_kf_message(access_token, user_id, open_kfid, content):
    response = requests.post(
        "https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg",
        params={"access_token": access_token},
        json={
            "touser": user_id,
            "open_kfid": open_kfid,
            "msgtype": "text",
            "text": {"content": content},
        },
        timeout=10,
    )
    response.raise_for_status()
    result = response.json()
    if result.get("errcode") != 0:
        raise RuntimeError(f"Failed to send customer-service message: errcode={result.get('errcode')}")


def process_and_reply(user_id, text_content, access_token, open_kfid):
    payload = {
        "user_id": user_id,
        "message": text_content,
        "access_token": access_token,
        "open_kfid": open_kfid,
    }
    try:
        response = requests.post(RPA_KF_WEBHOOK_URL, json=payload, timeout=15)
        response.raise_for_status()
        logger.info("RPA customer-service webhook accepted message: status=%s", response.status_code)
    except requests.RequestException as exc:
        logger.exception("RPA customer-service webhook failed: %s", exc)
        try:
            send_kf_message(access_token, user_id, open_kfid, "抱歉，服务器开小差了，请稍后再试。")
        except Exception as send_exc:
            logger.exception("Fallback reply failed: %s", send_exc)


def handle_kf_event(message_token, open_kfid):
    with cursor_lock:
        access_token = get_access_token()
        cursor = read_cursor()
        result = sync_kf_messages(access_token, message_token, cursor)
        if result.get("errcode") != 0:
            raise RuntimeError(f"Failed to sync messages: errcode={result.get('errcode')}")

        messages = result.get("msg_list", [])
        customer_texts = [
            item
            for item in messages
            if isinstance(item, dict)
            and item.get("msgtype") == "text"
            and item.get("origin") == 3
        ]

        next_cursor = result.get("next_cursor", cursor)
        if next_cursor:
            save_cursor(next_cursor)

    if not customer_texts:
        logger.info("No new customer text messages; event ignored")
        return

    forwarded = 0
    for item in customer_texts:
        user_id = item.get("external_userid", "")
        content = (item.get("text") or {}).get("content", "")
        if not user_id or not content:
            logger.info("Ignored incomplete customer text message")
            continue
        threading.Thread(
            target=process_and_reply,
            args=(user_id, content, access_token, open_kfid),
            daemon=True,
        ).start()
        forwarded += 1
    logger.info("Forwarded customer text messages: count=%s", forwarded)


@app.route("/wechatcallback", methods=["GET", "POST"])
def wechat_callback():
    msg_signature = request.args.get("msg_signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")

    if request.method == "GET":
        ret, echo_text = wxcpt.VerifyURL(
            msg_signature, timestamp, nonce, request.args.get("echostr", "")
        )
        if ret != 0:
            abort(403)
        return echo_text

    ret, plain_message = wxcpt.DecryptMsg(
        request.data, msg_signature, timestamp, nonce
    )
    if ret != 0:
        logger.warning("Message decryption failed: error=%s", ret)
        return "success"

    try:
        root = ET.fromstring(plain_message)
        event = root.findtext("Event", default="")
        if event != "kf_msg_or_event":
            return "success"

        message_token = root.findtext("Token", default="")
        open_kfid = root.findtext("OpenKfId", default="")
        if not message_token or not open_kfid:
            logger.warning("Incomplete customer-service event ignored")
            return "success"

        handle_kf_event(message_token, open_kfid)
    except Exception as exc:
        logger.exception("Failed to process customer-service callback: %s", exc)

    return "success"


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("KF_PORT", "8887")),
        debug=env_bool("FLASK_DEBUG"),
        use_reloader=False,
    )
