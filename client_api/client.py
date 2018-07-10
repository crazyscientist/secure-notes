#!/usr/bin/env python3

import json
import logging
import urllib.parse
import os
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import requests
import code


class AESKey(object):
    def __init__(self, key=None, iv=None):
        self.key = key or os.urandom(NotesAPIClient.AES_KEYSIZE)
        self.iv = iv or os.urandom(AES.block_size)
        self.aeskey = None

    def reset(self):
        self.aeskey = AES.new(self.key, AES.MODE_CFB, self.iv)

    def encrypt(self, text):
        self.reset()
        return self.aeskey.encrypt(text)

    def decrypt(self, text):
        self.reset()
        return self.aeskey.decrypt(text)

    def get_secret(self):
        return self.iv + self.key


class NotesAPIClient(object):
    """
    API client for the Secure Notes service
    """
    base_url = "http://localhost:8000/notes/"
    RSA_KEYSIZE = 2048
    AES_KEYSIZE = 32

    def __init__(self, username, password, rsa_password=None, logger=None):
        self.logger = logger
        self.username = username
        self.password = password
        self.rsa_password = rsa_password or password

        if logger is None:
            logging.basicConfig(level=logging.DEBUG)
            self.logger = logging.getLogger("NotesClient")

        self.rsa_key = None

    def __call__(self, *args, **kwargs):
        self.get_rsa_key()

    def _get_content(self, jsonstring):
        """
        Convert JSON string to dictionary
        :param jsonstring: JSON encoded string
        :type jsonstring: str
        :return: dict
        """
        return json.loads(jsonstring)

    def get_rsa_key(self, username=None):
        """
        Retrieve private/public RSA key for user ``username``.

        .. note:: The private key is only returned for you!

        :param username: Name of user for which keys are to be retrieved.
        :return: :py:obj:`Crypto.PublicKey.RSA._RSAobj` or ``None``
        """
        username = username or self.username
        url = urllib.parse.urljoin(self.base_url, "key/{}/".format(username))
        self.logger.debug("URL: {}".format(url))

        response = requests.get(
            url,
            auth=(self.username, self.password)
        )

        if response.status_code != 200:
            self.logger.error("Cannot get rsa keys: {}".format(response.status_code))
            return None

        content = self._get_content(response.content)
        if content.get("private_key"):
            key = RSA.importKey(content.get("private_key"), self.rsa_password)
        elif content.get("public_key"):
            key = RSA.importKey(content.get("public_key"))

        self.logger.debug("OK")
        return key

    def create_rsa_key(self):
        """
        Upload private/public key.

        .. note:: If replacing the upstream keys, ensure that encrypted data is re-crypted!

        :return: :py:obj:`Crypto.PublicKey.RSA._RSAobj` or ``None`
        """
        url = urllib.parse.urljoin(self.base_url, "key/{}/".format(self.username))
        self.logger.debug("URL: {}".format(url))

        key = RSA.generate(self.RSA_KEYSIZE)
        pub = key.publickey()

        data = {
            'private_key': key.exportKey("PEM", self.rsa_password),
            'public_key': pub.exportKey("PEM"),
            'username': self.username
        }

        response = requests.post(
            url,
            auth=(self.username, self.password),
            data=data
        )

        if response.status_code != 201:
            self.logger.error("Failed to upload RSA keys: {}".format(response.content))
            return None

        self.logger.debug("OK")
        return key

    def add_note(self, title, content):
        """
        Upload an encrypted note

        :param title: Title that is saved unencrypted
        :type title: str
        :param content: Content that is saved *encrypted*
        :type content: str
        :return: ``0`` if successful, otherwise ``1``
        """
        if self.rsa_key is None:
            self.rsa_key = self.get_rsa_key()

        aeskey = AESKey()
        data = {
            'title': title,
            'content': aeskey.encrypt(content)
        }

        response = requests.post(
            urllib.parse.urljoin(self.base_url, "note/"),
            auth=(self.username, self.password),
            data=data
        )

        if response.status_code != 201:
            self.logger.error("Failed to upload note")
            return 1

        content = self._get_content(response.content)

        if not content.get("id"):
            self.logger.error("Did not receive ID of newly created note")
            return 1

        return self.upload_aes_key(aeskey, content.get("id"))

    def upload_aes_key(self, aeskey, pk, username=None, rsakey=None):
        """
        Upload AES key ``aeskey`` that was used to encrypt note with id ``pk``

        :param aeskey: AES key that was used to encrypt data
        :type aeskey: :py:obj:`AESKey`
        :param pk: ID for the encrypted content that was given by the server
        :type pk: int
        :param username:
        :param rsakey:
        :return:
        """
        username = username or self.username
        rsakey = rsakey or self.rsa_key

        data = {
            'user': username,
            'key': rsakey.encrypt(aeskey.get_secret(), b"0")
        }

        response = requests.post(
            urllib.parse.urljoin(self.base_url, "note/{}/setkey".format(pk)),
            auth=(self.username, self.password),
            data=data
        )

        if response.status_code != 201:
            self.logger.error("Failed to upload AES key: {}".format(response.content))


if __name__ == '__main__':
    client = NotesAPIClient(*sys.argv[1:])
    client()