from django.db import models
from django.contrib.auth import models as authmodels

from notes import constants


# Create your models here.
class Content(models.Model):
    title = models.CharField(max_length=250, help_text="Plaintext title", null=True, default=None)
    content = models.TextField(help_text="Encrypted content", null=True, default=None)
    owner = models.ForeignKey(authmodels.User, help_text="Owner of this object", null=False, blank=False, on_delete=models.CASCADE)

    def __str__(self):
        return self.title


class Key(models.Model):
    content = models.ForeignKey(Content, help_text="Encrypted content", null=False, blank=False, on_delete=models.CASCADE, related_name="aeskey")
    key = models.CharField(max_length=(constants.CIPHER_AES_KEYSIZE+constants.CIPHER_AES_BLOCKSIZE)*4//3, help_text="Encrypted key", null=False, blank=False)
    user = models.ForeignKey(authmodels.User, null=False, blank=False, on_delete=models.CASCADE)
    is_revoked = models.BooleanField(help_text="Set to revoke access", default=False)

    def __str__(self):
        return "'{}' for {}".format(self.content.title, self.user.username)

    class Meta:
        unique_together = ('content', 'key', 'user')


class CryptoKey(models.Model):
    private_key = models.CharField(max_length=constants.CIPHER_RSA_KEYSIZE, help_text="RSA private key")
    public_key = models.CharField(max_length=constants.CIPHER_RSA_KEYSIZE, help_text="RSA public key")
    user = models.OneToOneField(authmodels.User, help_text="Authorized user to access content", on_delete=models.CASCADE)
    is_revoked = models.BooleanField(help_text="Set to revoke access", default=False)

    def __str__(self):
        return "Key for {}".format(self.user.username)

    class Meta:
        unique_together = ('private_key', 'public_key', 'user')