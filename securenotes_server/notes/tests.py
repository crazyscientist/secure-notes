import base64
import json
import os

from django.test import TestCase
from django.contrib.auth import models as authmodels
from django.core.exceptions import ObjectDoesNotExist
from django.urls.base import reverse

from rest_framework.test import APIClient, APIRequestFactory, force_authenticate
from notes import models


# Create your tests here.
class NotesTest(TestCase):

    def setUp(self):
        self.testuser = authmodels.User.objects.get_or_create(username="testsuer", password="password")[0]
        self.testnote = models.Content.objects.create(
            title="original title",
            content="original content",
            owner=self.testuser
        )
        self.newnotecontent = {
            'title': 'new title',
            'content': 'new content'
        }

        self.factory = APIRequestFactory()
        self.client = APIClient()

    def test_note_add(self):
        self.client.force_authenticate(self.testuser)
        response = self.client.post(
            reverse("note_add"),
            {
                'title': 'test',
                'content': 'encrypted',
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(models.Content.objects.filter(owner=self.testuser,title="test",content="encrypted").count(), 1)

    def test_note_edit(self):
        self.client.force_authenticate(self.testuser)

        response = self.client.put(
            reverse("note", args=[self.testnote.pk]),
            self.newnotecontent
        )

        self.assertEqual(response.status_code, 200)
        obj = models.Content.objects.get(pk=self.testnote.pk)
        self.assertEqual(obj.title, self.newnotecontent["title"])
        self.assertEqual(obj.content, self.newnotecontent["content"])

    def test_note_edit_prohibit(self):
        testuser2 = authmodels.User.objects.create(username="testuser2", password="password")
        self.client.force_authenticate(testuser2)

        response = self.client.put(
            reverse("note", args=[self.testnote.pk]),
            self.newnotecontent
        )

        self.assertEqual(response.status_code, 403)
        obj = models.Content.objects.get(pk=self.testnote.pk)
        self.assertNotEqual(obj.title, self.newnotecontent["title"])
        self.assertNotEqual(obj.content, self.newnotecontent["content"])

    def test_note_delete(self):
        self.client.force_authenticate(self.testuser)

        response = self.client.delete(reverse("note", args=[self.testnote.pk]))

        self.assertEqual(response.status_code, 204)
        self.assertRaises(ObjectDoesNotExist, models.Content.objects.get,pk=self.testnote.pk)

    def test_note_delete_prohibit(self):
        testuser2 = authmodels.User.objects.create(username="testuser2", password="password")
        self.client.force_authenticate(testuser2)

        response = self.client.delete(reverse("note", args=[self.testnote.pk]))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(models.Content.objects.filter(pk=self.testnote.pk).count(),1)

    def test_rsakey_add(self):
        self.client.force_authenticate(self.testuser)
        response = self.client.post(
            reverse("rsa_keys", args=[self.testuser.username]),
            {"private_key": "private_key", "public_key": "public_key"}
        )
        self.assertEqual(response.status_code, 201)

    def test_rsakey_add_duplicate(self):
        models.CryptoKey.objects.create(
            private_key="private_key",
            public_key="public_key",
            user=self.testuser
        )

        self.client.force_authenticate(self.testuser)
        response = self.client.post(
            reverse("rsa_keys", args=[self.testuser.username]),
            {"private_key": "private_key", "public_key": "public_key"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(models.CryptoKey.objects.filter(user=self.testuser).count(), 1)

    def test_rsakey_add_otheruser(self):
        testuser2 = authmodels.User.objects.create(username="testuser2", password="password")
        testuser_key = models.CryptoKey.objects.create(private_key="private_key", public_key="public_key", user=self.testuser)
        self.client.force_authenticate(self.testuser)
        response = self.client.post(
            reverse("rsa_keys", args=[self.testuser.username]),
            {"private_key": "private_key2", "public_key": "public_key2", "username": testuser2.username}
        )

        self.assertEqual(response.status_code, 403)
        obj = models.CryptoKey.objects.get(pk=testuser_key.pk)
        self.assertEqual(testuser_key.private_key, obj.private_key)
        self.assertEqual(models.CryptoKey.objects.filter(user=testuser2).count(), 0)

    def test_rsakey_delete(self):
        self.assertEqual(models.CryptoKey.objects.filter(user=self.testuser).count(), 0)
        testuser_key = models.CryptoKey.objects.create(private_key="private_key", public_key="public_key", user=self.testuser)
        self.client.force_authenticate(self.testuser)
        response = self.client.delete(reverse("rsa_keys", args=[testuser_key.user.username]))
        del testuser_key

        self.assertEqual(response.status_code, 204)
        self.assertEqual(models.CryptoKey.objects.filter(user=self.testuser).count(), 0)

    def test_rsakey_delete_otheruser(self):
        testuser2 = authmodels.User.objects.create(username="testuser2", password="password")
        testuser2_key = models.CryptoKey.objects.create(private_key="private_key", public_key="public_key", user=testuser2)

        self.client.force_authenticate(self.testuser)
        response = self.client.delete(reverse("rsa_keys", args=[testuser2.username]))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(models.CryptoKey.objects.filter(user=testuser2).count(), 1)

    def test_rsakey_put(self):
        def basetest(org, data, expected):
            response = self.client.put(reverse("rsa_keys", args=[self.testuser.username]), data)
            self.assertEqual(response.status_code, expected, response.content)
            rsakey = models.CryptoKey.objects.get(user=org.get("user", None))
            self.assertEqual(rsakey.private_key, org.get("private_key", None))
            self.assertEqual(rsakey.public_key, org.get("public_key", None))
            self.assertEqual(rsakey.is_revoked, data.get("is_revoked", None))

        self.client.force_authenticate(self.testuser)
        org= {"private_key": "private_key", "public_key": "public_key", "user": self.testuser, "is_revoked": False}
        key = models.CryptoKey.objects.create(**org)

        for data, expected in [
            [{"is_revoked": True}, 200],
            [{"is_revoked": False}, 200],
            [{"is_revoked": False, 'private_key': '123'}, 200],
        ]:
            basetest(org, data, expected)

    def test_rsakey_get(self):
        key = models.CryptoKey.objects.create(private_key="private", public_key="public", user=self.testuser)
        self.client.force_authenticate(user=self.testuser)

        response = self.client.get(reverse("rsa_keys", args=[self.testuser.username]))
        content = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(content.get("private_key"), key.private_key)
        self.assertEqual(content.get("public_key"), key.public_key)

    def test_rsakey_get_otheruser(self):
        key = models.CryptoKey.objects.create(private_key="private", public_key="public", user=self.testuser)
        testuser2 = authmodels.User.objects.create(username="testuser2", password="password")
        self.client.force_authenticate(user=testuser2)

        response = self.client.get(reverse("rsa_keys", args=[self.testuser.username]))
        content = json.loads(response.content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(content.get("private_key", None), None)
        self.assertEqual(content.get("public_key"), key.public_key)

    def test_rsakey_get_revoked(self):
        key = models.CryptoKey.objects.create(private_key="private", public_key="public", user=self.testuser, is_revoked=True)
        self.client.force_authenticate(user=self.testuser)

        response = self.client.get(reverse("rsa_keys", args=[self.testuser.username]))
        self.assertEqual(response.status_code, 404)

    def test_aeskey_set(self):
        self.client.force_authenticate(user=self.testuser)
        response = self.client.post(
            reverse("aes_keys_set", args=[self.testnote.pk]),
            data={"key": "aeskey", "user": self.testuser.username}
        )

        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(models.Key.objects.filter(content=self.testnote, user=self.testuser, key="aeskey").count(), 1)

    def test_aeskey_set_otheruser(self):
        testuser2 = authmodels.User.objects.create(username="t", password="p")
        self.client.force_authenticate(user=self.testuser)
        response = self.client.post(
            reverse("aes_keys_set", args=[self.testnote.pk]),
            data={"key": "shared", "user": testuser2.username}
        )

        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(models.Key.objects.filter(content=self.testnote, user=testuser2, key="shared").count(), 1)

    def test_aeskey_set_prohibit(self):
        testuser2 = authmodels.User.objects.create(username="t", password="p")
        testuser3 = authmodels.User.objects.create(username="t3", password="p")
        self.client.force_authenticate(user=testuser2)
        response = self.client.post(
            reverse("aes_keys_set", args=[self.testnote.pk]),
            data={"key": "otherkey", "user": testuser3.username}
        )

        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(models.Key.objects.filter(content=self.testnote, user=testuser3, key="otherkey").count(), 0)

    def test_aeskey_set_notfound(self):
        self.client.force_authenticate(user=self.testuser)
        response = self.client.post(
            reverse("aes_keys_set", args=[99]),
            data={"key": "aeskey", "user": self.testuser.username}
        )

        self.assertEqual(response.status_code, 404, response.content)

    def test_aeskey_get(self):
        key = models.Key.objects.create(key="secretkey", user=self.testuser, content=self.testnote)
        self.client.force_authenticate(user=self.testuser)
        response = self.client.get(
            reverse("aes_keys_get", args=[self.testnote.pk])
        )
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content)
        self.assertEqual(content.get("key", None), key.key)

    def test_aeskey_get_otheruser(self):
        testuser2 = authmodels.User.objects.create(username="t", password="p")
        key = models.Key.objects.create(key="secretkey", user=self.testuser, content=self.testnote)
        self.client.force_authenticate(user=testuser2)
        response = self.client.get(
            reverse("aes_keys_get", args=[self.testnote.pk]),
            data={"user": self.testuser.username}
        )
        self.assertEqual(response.status_code, 404)

    def test_aeskey_get_revoked(self):
        key = models.Key.objects.create(key="secretkey", user=self.testuser, content=self.testnote, is_revoked=True)
        self.client.force_authenticate(user=self.testuser)
        response = self.client.get(
            reverse("aes_keys_get", args=[self.testnote.pk])
        )
        self.assertEqual(response.status_code, 404)

    def test_aeskey_put(self):
        def basetest(org, data, expected, user):
            self.client.force_authenticate(user=user)
            response = self.client.put(
                reverse("aes_keys_set", args=[self.testnote.pk]),
                data
            )

            key = models.Key.objects.get(pk=org["pk"])
            self.assertEqual(response.status_code, expected)
            self.assertEqual(key.key, org.get("key", None))
            self.assertEqual(key.content, org.get("content", None))
            self.assertEqual(key.user, org.get("user", None))
            if "is_revoked" in data and key.user == user:
                self.assertEqual(key.is_revoked, data.get("is_revoked"))
            else:
                self.assertEqual(key.is_revoked, org["is_revoked"])

        testuser2 = authmodels.User.objects.create(username="t", password="p")
        org = {"content": self.testnote, "key": "original key", "user": self.testuser, "is_revoked": False}
        key = models.Key.objects.create(**org)
        org["pk"] = key.pk

        for data, expected, user in [
            [{"is_revoked": True}, 200, self.testuser],
            [{"is_revoked": False}, 200, self.testuser],
            [{"is_revoked": True}, 403, testuser2],
            [{"is_revoked": False}, 403, testuser2],
            [{"is_revoked": True, "key": "another key"}, 200, self.testuser],
            [{"is_revoked": False, "key": "another key"}, 200, self.testuser],
            [{"is_revoked": True, "key": "another key"}, 403, testuser2],
            [{"is_revoked": False, "key": "another key"}, 403, testuser2],
        ]:
            basetest(org, data, expected, user)

    def test_aeskey_delete(self):
        def basetest(authuser, user, username):
            key = models.Key.objects.get_or_create(content=self.testnote, key="secret", user=user)

            self.client.force_authenticate(user=authuser)
            response = self.client.delete(
                reverse("aes_keys_del", args=[self.testnote.pk, username])
            )

            if authuser.username == self.testnote.owner.username and user.username == username:
                self.assertEqual(response.status_code, 204)
            elif authuser.username == self.testnote.owner.username and user.username != username:
                self.assertEqual(response.status_code, 404)
            elif authuser.username != self.testnote.owner.username:
                self.assertEqual(response.status_code, 403)
            else:
                self.assertNotEqual(response.status_code, 204)

        for authuser, user, username in [
            ["testuser", "t", "t"],
            ["testuser", "t", "f"],
            ["a", "t", "t"],
            ["a", "t", "f"]
        ]:
            basetest(
                authmodels.User.objects.get_or_create(username=authuser)[0],
                authmodels.User.objects.get_or_create(username=user)[0],
                username
            )