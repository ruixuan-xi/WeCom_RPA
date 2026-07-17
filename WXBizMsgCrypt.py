import base64
import string
import random
import hashlib
import time
import struct
from Crypto.Cipher import AES
import xml.etree.cElementTree as ET
import socket

# 我把报错字典直接集成进来了，从此再也不需要依赖 ierror.py
class ierror:
    WXBizMsgCrypt_OK = 0
    WXBizMsgCrypt_ValidateSignature_Error = -40001
    WXBizMsgCrypt_ParseXml_Error = -40002
    WXBizMsgCrypt_ComputeSignature_Error = -40003
    WXBizMsgCrypt_IllegalAesKey = -40004
    WXBizMsgCrypt_ValidateCorpid_Error = -40005
    WXBizMsgCrypt_EncryptAES_Error = -40006
    WXBizMsgCrypt_DecryptAES_Error = -40007
    WXBizMsgCrypt_IllegalBuffer = -40008
    WXBizMsgCrypt_EncodeBase64_Error = -40009
    WXBizMsgCrypt_DecodeBase64_Error = -40010
    WXBizMsgCrypt_GenReturnXml_Error = -40011

class SHA1:
    def getSHA1(self, token, timestamp, nonce, encrypt):
        try:
            sortlist = [token, timestamp, nonce, encrypt]
            sortlist.sort()
            sha = hashlib.sha1()
            # 修复了字符串编码计算 Hash 的 Bug
            sha.update("".join(sortlist).encode('utf-8'))
            return ierror.WXBizMsgCrypt_OK, sha.hexdigest()
        except Exception as e:
            return ierror.WXBizMsgCrypt_ComputeSignature_Error, None

class XMLParse:
    AES_TEXT_RESPONSE_TEMPLATE = """<xml>
<Encrypt><![CDATA[%(msg_encrypt)s]]></Encrypt>
<MsgSignature><![CDATA[%(msg_signaturet)s]]></MsgSignature>
<TimeStamp>%(timestamp)s</TimeStamp>
<Nonce><![CDATA[%(nonce)s]]></Nonce>
</xml>"""
    def extract(self, xmltext):
        try:
            xml_tree = ET.fromstring(xmltext)
            encrypt  = xml_tree.find("Encrypt")
            return ierror.WXBizMsgCrypt_OK, encrypt.text
        except Exception as e:
            return ierror.WXBizMsgCrypt_ParseXml_Error,None

    def generate(self, encrypt, signature, timestamp, nonce):
        resp_dict = {
                    'msg_encrypt' : encrypt,
                    'msg_signaturet': signature,
                    'timestamp'    : timestamp,
                    'nonce'        : nonce,
                     }
        resp_xml = self.AES_TEXT_RESPONSE_TEMPLATE % resp_dict
        return resp_xml

class PKCS7Encoder():
    block_size = 32
    def encode(self, text):
        text_length = len(text)
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        pad = chr(amount_to_pad)
        return text + (pad * amount_to_pad).encode('utf-8')

    def decode(self, decrypted):
        pad = decrypted[-1]
        if pad < 1 or pad > 32:
            pad = 0
        return decrypted[:-pad]

class Prpcrypt(object):
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CBC

    def encrypt(self, text, receiveid):
        text = text.encode('utf-8')
        receiveid = receiveid.encode('utf-8')
        text = self.get_random_str().encode('utf-8') + struct.pack("I", socket.htonl(len(text))) + text + receiveid
        pkcs7 = PKCS7Encoder()
        text = pkcs7.encode(text)
        cryptor = AES.new(self.key, self.mode, self.key[:16])
        try:
            ciphertext = cryptor.encrypt(text)
            return ierror.WXBizMsgCrypt_OK, base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            return ierror.WXBizMsgCrypt_EncryptAES_Error, None

    def decrypt(self, text, receiveid):
        try:
            cryptor = AES.new(self.key, self.mode, self.key[:16])
            plain_text = cryptor.decrypt(base64.b64decode(text))
        except Exception as e:
            return ierror.WXBizMsgCrypt_DecryptAES_Error, None
        try:
            pad = plain_text[-1]
            content = plain_text[16:-pad]
            xml_len = socket.ntohl(struct.unpack("I", content[:4])[0])
            xml_content = content[4:xml_len+4]
            # 修复了 Python 3 下 Bytes 与 String 校验对比的 Bug
            from_receiveid = content[xml_len+4:].decode('utf-8')
        except Exception as e:
            return ierror.WXBizMsgCrypt_IllegalBuffer, None

        if from_receiveid != receiveid:
            return ierror.WXBizMsgCrypt_ValidateCorpid_Error, None
        return ierror.WXBizMsgCrypt_OK, xml_content.decode('utf-8')

    def get_random_str(self):
        rule = string.ascii_letters + string.digits
        str_list = random.sample(rule, 16)
        return "".join(str_list)

class WXBizMsgCrypt(object):
    def __init__(self, sToken, sEncodingAESKey, sReceiveId):
        try:
            self.key = base64.b64decode(sEncodingAESKey + "=")
            assert len(self.key) == 32
        except:
            raise Exception("[error]: EncodingAESKey unvalid !")
        self.m_sToken = sToken
        self.m_sReceiveId = sReceiveId

    def VerifyURL(self, sMsgSignature, sTimeStamp, sNonce, sEchoStr):
        sha1 = SHA1()
        ret, signature = sha1.getSHA1(self.m_sToken, sTimeStamp, sNonce, sEchoStr)
        if ret != 0:
            return ret, None
        if not signature == sMsgSignature:
            return ierror.WXBizMsgCrypt_ValidateSignature_Error, None
        pc = Prpcrypt(self.key)
        ret, sReplyEchoStr = pc.decrypt(sEchoStr, self.m_sReceiveId)
        return ret, sReplyEchoStr

    def EncryptMsg(self, sReplyMsg, sNonce, timestamp=None):
        pc = Prpcrypt(self.key)
        ret, encrypt = pc.encrypt(sReplyMsg, self.m_sReceiveId)
        if ret != 0:
            return ret, None
        if timestamp is None:
            timestamp = str(int(time.time()))
        sha1 = SHA1()
        ret, signature = sha1.getSHA1(self.m_sToken, timestamp, sNonce, encrypt)
        if ret != 0:
            return ret, None
        xmlParse = XMLParse()
        return ret, xmlParse.generate(encrypt, signature, timestamp, sNonce)

    def DecryptMsg(self, sPostData, sMsgSignature, sTimeStamp, sNonce):
        xmlParse = XMLParse()
        ret, encrypt = xmlParse.extract(sPostData)
        if ret != 0:
            return ret, None
        sha1 = SHA1()
        ret, signature = sha1.getSHA1(self.m_sToken, sTimeStamp, sNonce, encrypt)
        if ret != 0:
            return ret, None
        if not signature == sMsgSignature:
            return ierror.WXBizMsgCrypt_ValidateSignature_Error, None
        pc = Prpcrypt(self.key)
        ret, xml_content = pc.decrypt(encrypt, self.m_sReceiveId)
        return ret, xml_content