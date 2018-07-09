from rest_framework import serializers
from notes import models


class KeySerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Key
        fields = ('key',)


class ContentSerializer(serializers.ModelSerializer):
    aeskey = KeySerializer(read_only=True, many=True)

    class Meta:
        model = models.Content
        fields = ('title', 'content', 'aeskey')


class CryptoKeySerializer(serializers.ModelSerializer):
    username = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = models.CryptoKey
        fields = ('private_key', 'public_key', 'username')