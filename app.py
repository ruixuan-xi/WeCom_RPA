import logging

from flask import Flask, abort, request

from WXBizMsgCrypt import WXBizMsgCrypt
from config import env_bool, required_env

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

WECOM_TOKEN = required_env("WECOM_TOKEN")
WECOM_ENCODING_AES_KEY = required_env("WECOM_ENCODING_AES_KEY")
WECOM_CORP_ID = required_env("WECOM_CORP_ID")
wxcpt = WXBizMsgCrypt(WECOM_TOKEN, WECOM_ENCODING_AES_KEY, WECOM_CORP_ID)


@app.get("/wecom/callback")
def verify_url():
    msg_signature = request.args.get("msg_signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    echostr = request.args.get("echostr", "")

    ret, echo_text = wxcpt.VerifyURL(msg_signature, timestamp, nonce, echostr)
    if ret != 0:
        logger.warning("URL verification failed: error=%s", ret)
        abort(403)
    return echo_text


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(__import__("os").getenv("VERIFY_PORT", "5000")),
        debug=env_bool("FLASK_DEBUG"),
    )
