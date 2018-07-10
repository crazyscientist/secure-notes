from django.contrib.auth import models as authmodels
from rest_framework import serializers
from notes import models


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = authmodels.User
        fields = ('username', )


class KeySerializer(serializers.ModelSerializer):
    user = serializers.SlugRelatedField(queryset=authmodels.User.objects.all(), slug_field="username")
    key = serializers.CharField()
    is_revoked = serializers.BooleanField(write_only=True, required=False)

    class Meta:
        model = models.Key
        fields = ('key', 'user', 'is_revoked')


class ContentSerializer(serializers.ModelSerializer):
    owner = serializers.SlugRelatedField(slug_field="username", read_only=True)

    class Meta:
        model = models.Content
        fields = ('title', 'content', 'id', 'owner')


class CryptoKeySerializer(serializers.ModelSerializer):
    username = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = models.CryptoKey
        fields = ('private_key', 'public_key', 'username')