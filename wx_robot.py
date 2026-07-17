import json
import logging
import os
import xml.etree.ElementTree as ET

import requests
from flask import Flask, request

from WXBizMsgCrypt import WXBizMsgCrypt
from config import env_bool, required_env

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

WECOM_TOKEN = required_env("WECOM_TOKEN")
WECOM_ENCODING_AES_KEY = required_env("WECOM_ENCODING_AES_KEY")
WECOM_CORP_ID = required_env("WECOM_CORP_ID")
RPA_ROBOT_WEBHOOK_URL = required_env("RPA_ROBOT_WEBHOOK_URL")
wxcpt = WXBizMsgCrypt(WECOM_TOKEN, WECOM_ENCODING_AES_KEY, WECOM_CORP_ID)


def xml_text(root, name, default=""):
    node = root.find(name)
    return node.text if node is not None and node.text is not None else default


def parse_message(message):
    response_url = ""
    if message.lstrip().startswith("{"):
        data = json.loads(message)
        text = data.get("text") or {}
        sender = data.get("from") or {}
        return {
            "content": text.get("content", data.get("Content", "")),
            "user_id": data.get("FromUserName", sender.get("userid", sender.get("userId", ""))),
            "chat_id": data.get("ToUserName", data.get("to", "")),
            "msg_id": data.get("MsgId", data.get("msgid", "")),
            "chat_type": data.get("ChatType", data.get("chattype", "single")),
            "response_url": data.get("response_url", ""),
        }

    root = ET.fromstring(message)
    response_url = xml_text(root, "response_url")
    return {
        "content": xml_text(root, "Content"),
        "user_id": xml_text(root, "FromUserName"),
        "chat_id": xml_text(root, "ToUserName"),
        "msg_id": xml_text(root, "MsgId"),
        "chat_type": xml_text(root, "ChatType", "single"),
        "response_url": response_url,
    }


def forward_to_rpa(payload):
    response = requests.post(RPA_ROBOT_WEBHOOK_URL, json=payload, timeout=10)
    response.raise_for_status()
    logger.info(
        "RPA webhook accepted message: status=%s msg_id=%s chat_type=%s",
        response.status_code,
        payload.get("msg_id"),
        payload.get("chat_type"),
    )


@app.route("/wecom/callback", methods=["GET", "POST"])
def wecom_callback():
    msg_signature = request.args.get("msg_signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")

    if request.method == "GET":
        echostr = request.args.get("echostr", "")
        ret, echo_text = wxcpt.VerifyURL(msg_signature, timestamp, nonce, echostr)
        return echo_text if ret == 0 else ("forbidden", 403)

    encrypted_body = request.get_data()
    if encrypted_body.lstrip().startswith(b"{"):
        envelope = request.get_json(silent=True) or {}
        encrypted = envelope.get("encrypt", "")
        encrypted_body = (
            f"<xml><Encrypt><![CDATA[{encrypted}]]></Encrypt></xml>".encode("utf-8")
        )

    ret, plain_message = wxcpt.DecryptMsg(
        encrypted_body, msg_signature, timestamp, nonce
    )
    if ret != 0:
        logger.warning("Message decryption failed: error=%s", ret)
        return "success"

    try:
        payload = parse_message(plain_message)
        if not payload["content"]:
            logger.info("Ignored non-text or empty message")
            return "success"
        forward_to_rpa(payload)
    except (ValueError, ET.ParseError, requests.RequestException) as exc:
        logger.exception("Failed to process callback: %s", exc)

    return "success"


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("ROBOT_PORT", "5000")),
        debug=env_bool("FLASK_DEBUG"),
    )
