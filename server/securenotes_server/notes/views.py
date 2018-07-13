"""
The views (aka. API endpoints) provide atomic functionality. To successfully save an encrypted note such that it can be
accessed again at a later point of time multiple requests are required. The server does not verify that content is
encrypted, it merely provides the means to store encrypted data and grant access to other users.

The following diagram illustrates the concept:

.. uml::
    :caption: Steps to upload note and corresponding keys

    |Client|
    start
    :get or create RSA keys;
    |Server|
    :save RSA keys;
    |Client|
    :get or create AES key;
    :enrypt data;
    :encode data with Base64;
    |Server|
    :save encrypted data;
    |Client|
    :encrypt AES key with RSA;
    :encode key with Base64;
    |Server|
    :save encrypted AES key;
    stop
"""
from django.db import transaction
from django.db.utils import IntegrityError
from django.contrib.auth import models as authmodels
from django.core.exceptions import ValidationError
from django.http import Http404
from django.db.models import Q
from rest_framework import exceptions, generics, mixins, permissions, viewsets
from rest_framework.exceptions import PermissionDenied

from notes import models, serializers
from notes import mixins as mymixins
from django.shortcuts import get_object_or_404 as _get_object_or_404


def get_object_or_404(queryset, *filter_args, **filter_kwargs):
    """
    Same as Django's standard shortcut, but make sure to also raise 404
    if the filter_kwargs don't match the required types.
    """
    try:
        return _get_object_or_404(queryset, *filter_args, **filter_kwargs)
    except (TypeError, ValueError, ValidationError):
        raise


# Create your views here.
class CryptoView(mixins.CreateModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin, mixins.UpdateModelMixin, generics.GenericAPIView):
    """
    View for managing keys for asymmetric encryption.
    """
    queryset = models.CryptoKey.objects.all()
    lookup_url_kwarg = 'username'
    lookup_field = 'user__username'
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = serializers.CryptoKeySerializer

    def __init__(self, *args, **kwargs):
        self.user = None
        super(CryptoView, self).__init__(*args, **kwargs)

    def get_serializer_class(self):
        if self.request.method == "PUT":
            return serializers.CryptoKeyPutSerializer

        return self.serializer_class

    def check_user(self, request, *args, **kwargs):
        key = get_object_or_404(models.CryptoKey.objects.all(), user__username=kwargs.get("username"))
        if key is None:
            raise Http404
        if request.user != key.user:
            raise PermissionDenied("You are not the owner")

    def get(self, request, *args, **kwargs):
        """
        Using the GET method returns an RSA key.

        If a user requests the key for himself, the private key is returned. Otherwise the public key.
        """
        self.queryset = self.queryset.filter(is_revoked=False)
        response = self.retrieve(request, *args, **kwargs)
        if request.user.username != kwargs.get("username"):
            del response.data["private_key"]
        return response

    def post(self, request, *args, **kwargs):
        """
        Using the POST method the private and public key are stored
        """
        self.user = request.user
        return self.create(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        """
        Using the PUT method a key pair can be revoked

        .. note::

            This method does not allow to change stored keys!
            Replacing the keys would render stored data inaccessible.
        """
        self.check_user(request, *args, **kwargs)
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """
        Using the DELETE method a key pair is deleted
        """
        self.check_user(request, *args, **kwargs)
        return self.destroy(request, *args, **kwargs)

    def perform_create(self, serializer):
        try:
            with transaction.atomic():
                serializer.save(user=self.user)
        except IntegrityError:
            raise exceptions.PermissionDenied("Already a key present")

    def perform_update(self, serializer):
        for key in ["private_key", "public_key"]:
            serializer.validated_data.pop(key, None)
        serializer.save()


class ContentListView(mixins.ListModelMixin, generics.GenericAPIView):
    """
    View returning paginated content
    """
    queryset = models.Content.objects.distinct().order_by("pk")
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = serializers.ContentListSerializer

    def get(self, request, *args, **kwargs):
        """
        The GET method returns a list of unencrypted components of stored content

        This method only returns objects for which the requesting user is authorized. Authorization is solely checked
        against the existence of a symmetric encryption key and its revokation status.

        .. note::

            If an owner revokes his own symmetric key, the object will not be returned. The owner can however revoke
            the revokation of his key.
        """
        self.queryset = self.queryset.filter(aeskey__user__username=request.user.username).filter(aeskey__is_revoked=False)
        return self.list(request, *args, **kwargs)


class ContentCreateView(mixins.CreateModelMixin, generics.GenericAPIView):
    """
    View for storing content
    """
    serializer_class = serializers.ContentSerializer

    def __init__(self, *args, **kwargs):
        self.user = None
        super(ContentCreateView, self).__init__(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.user = request.user
        return self.create(request, *args, **kwargs)

    def perform_create(self, serializer):
        serializer.save(owner=self.user)


class ContentView(mixins.UpdateModelMixin, mixins.DestroyModelMixin, mixins.RetrieveModelMixin, generics.GenericAPIView):
    """
    View for handling existing objects
    """
    queryset = models.Content.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = serializers.ContentSerializer

    def check_owner(self, request, *args, **kwargs):
        content = get_object_or_404(models.Content.objects.all(), pk=kwargs.get("pk"))
        if content is None:
            raise Http404
        if request.user != content.owner:
            raise PermissionDenied("You are not the owner")

    def check_allowed(self, request, *args, **kwargs):
        content = get_object_or_404(self.queryset.filter(Q(owner=request.user)|Q(aeskey__user=request.user, aeskey__is_revoked=False)), pk=kwargs.get("pk"))
        if content is None:
            raise Http404

    def get(self, request, *args, **kwargs):
        """
        The GET method returns the data of a single object
        """
        self.check_allowed(request, *args, **kwargs)
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        """
        The PUT method updates the object in the database
        """
        self.check_owner(request, *args, **kwargs)
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """
        The DELETE method removes an object in the database
        """
        self.check_owner(request, *args, **kwargs)
        return self.destroy(request, *args, **kwargs)


class KeyListView(mixins.ListModelMixin, generics.GenericAPIView):
    """
    View providing a list of users associated with a content object
    """
    queryset = models.Key.objects.all().order_by("is_revoked")
    serializer_class = serializers.KeyListSerializer
    permission_classes = (permissions.IsAuthenticated, )
    lookup_field = 'content__pk'
    lookup_url_kwarg = 'content_id'

    def check_owner(self, request, *args, **kwargs):
        content = get_object_or_404(models.Content.objects.all(), pk=kwargs.get("content_id"))
        if content is None:
            raise Http404

        if request.user != content.owner:
            raise PermissionDenied("You are not the owner")
        self.content_id = int(kwargs.get("content_id", -1))

    def get(self, request, *args, **kwargs):
        """
        The GET method returns the list

        If a key for symmetric encryption was shared with a user and this key was revoked, the user and revokation
        status of the key are still in the list.
        """
        self.check_owner(request, *args, **kwargs)
        self.queryset = self.queryset.filter(content_id=kwargs.get("content_id"))
        return self.list(request, *args, **kwargs)


class KeyView(mixins.RetrieveModelMixin, mixins.CreateModelMixin, mixins.UpdateModelMixin, mixins.DestroyModelMixin, mymixins.MultipleFieldLookupMixin, viewsets.GenericViewSet):
    """
    View for managing keys for symmetric encryption

    .. important::

        The keys stored in this view should be encrypted with the public key of a user!
    """
    queryset = models.Key.objects.all()
    serializer_class = serializers.KeySerializer
    permission_classes = (permissions.IsAuthenticated, )
    lookup_url_kwarg = ('content_id', 'username')
    lookup_field = ('content_id', 'user__username')

    def get_serializer_class(self):
        if self.request.method == "PUT":
            return serializers.KeyPutSerializer

        return self.serializer_class

    def get(self, request, *args, **kwargs):
        """
        The GET method returns a key and its revokation status.

        If the requesting user is enquiring for a different username, the key is **not** included in the response!
        """
        self.queryset = self.queryset.filter(user__username=kwargs.get("username", request.user.username))
        response = self.retrieve(request, *args, **kwargs)
        if "key" in response.data and (
            request.user.username != kwargs.get("username", request.user.username)
            or
            response.data.get("is_revoked") is True
        ):
            del response.data["key"]
        return response

    def perform_create(self, serializer):
        serializer.save(content_id=self.content_id, is_revoked=False, user=self.user)

    def check_owner(self, request, *args, **kwargs):
        content = get_object_or_404(models.Content.objects.all(), pk=kwargs.get("content_id"))
        if content is None:
            raise Http404

        if request.user != content.owner:
            raise PermissionDenied("You are not the owner")
        self.content_id = int(kwargs.get("content_id", -1))

    def post(self, request, *args, **kwargs):
        """
        The POST method stores a new encryption key
        """
        self.check_owner(request, *args, **kwargs)
        self.user = authmodels.User.objects.get(username=kwargs.pop("username", request.user.username))
        return self.create(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        """
        The PUT method only sets the revokation status of a key
        """
        self.check_owner(request, *args, **kwargs)
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """
        The DELETE method removes a key from the database
        """
        self.check_owner(request, *args, **kwargs)
        self.queryset = self.queryset.filter(user__username=kwargs.pop("username", None))
        return self.destroy(request, *args, **kwargs)