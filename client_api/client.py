#!/usr/bin/env python3

import json
import logging
import urllib.parse
import sys

from Crypto.PublicKey import RSA
import requests
import code


class NotesAPIClient(object):
    """
    API client for the Secure Notes service
    """
    base_url = "http://localhost:8000/notes/"
    RSA_KEYSIZE = 2048

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

        return key

    def create_rsa_key(self):
        """
        Upload private/public key.

        .. note:: If replacing the upstream keys, ensure that encrypted data is re-crypted!

        :return: None
        :raises Error: if operation fails
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

        return key


if __name__ == '__main__':
    client = NotesAPIClient(*sys.argv[1:])
    client()