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
        self.queryset = self.queryset.filter(is_revoked=False)
        response = self.retrieve(request, *args, **kwargs)
        if request.user.username != kwargs.get("username"):
            del response.data["private_key"]
        return response

    def post(self, request, *args, **kwargs):
        self.user = request.user
        return self.create(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        self.check_user(request, *args, **kwargs)
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
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
    queryset = models.Content.objects.distinct().order_by("pk")
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = serializers.ContentSerializer

    def get(self, request, *args, **kwargs):
        self.queryset = self.queryset.filter(aeskey__user__username=request.user.username).filter(aeskey__is_revoked=False)
        return self.list(request, *args, **kwargs)


class ContentCreateView(mixins.CreateModelMixin, generics.GenericAPIView):
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
        self.check_allowed(request, *args, **kwargs)
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        self.check_owner(request, *args, **kwargs)
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        self.check_owner(request, *args, **kwargs)
        return self.destroy(request, *args, **kwargs)


class KeyView(mixins.RetrieveModelMixin, mixins.CreateModelMixin, mixins.UpdateModelMixin, mixins.DestroyModelMixin, mymixins.MultipleFieldLookupMixin, viewsets.GenericViewSet):
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
        self.check_owner(request, *args, **kwargs)
        self.user = authmodels.User.objects.get(username=kwargs.pop("username", request.user.username))
        return self.create(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        self.check_owner(request, *args, **kwargs)
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        self.check_owner(request, *args, **kwargs)
        self.queryset = self.queryset.filter(user__username=kwargs.pop("username", None))
        return self.destroy(request, *args, **kwargs)