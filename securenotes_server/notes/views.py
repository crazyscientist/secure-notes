from django.db.utils import IntegrityError
from django.core.exceptions import ValidationError
from django.http import Http404
from django.contrib.auth import models as authmodels
from rest_framework import exceptions, generics, mixins, permissions, status
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied

from notes import models, serializers
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
class CryptoView(mixins.CreateModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin, generics.GenericAPIView):
    queryset = models.CryptoKey.objects.all()
    lookup_url_kwarg = 'username'
    lookup_field = 'user__username'
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = serializers.CryptoKeySerializer

    def __init__(self, *args, **kwargs):
        self.user = None
        super(CryptoView, self).__init__(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        response = self.retrieve(request, *args, **kwargs)
        if request.user.username != kwargs.get("username"):
            del response.data["private_key"]
        return response

    def post(self, request, *args, **kwargs):
        self.user = request.user
        return self.create(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        self.destroy(request, *args, **kwargs)

    def perform_create(self, serializer):
        try:
            serializer.save(user=self.user)
        except IntegrityError:
            raise exceptions.PermissionDenied("Already a key present")


class ContentListView(mixins.ListModelMixin, generics.GenericAPIView):
    queryset = models.Content.objects.distinct().order_by("pk")
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = serializers.ContentSerializer

    def get(self, request, *args, **kwargs):
        self.queryset = self.queryset.filter(aeskey__user__username=request.user.username).filter(aeskey__is_revoked=False)
        print("DEBUG: GET:", self.queryset)
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

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)


class KeyView(mixins.RetrieveModelMixin, generics.GenericAPIView):
    queryset = models.Key.objects.all()
    serializer_class = serializers.KeySerializer
    permission_classes = (permissions.IsAuthenticated, )
    lookup_field = 'content_id'

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())

        # Perform the lookup filtering.
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field

        assert lookup_url_kwarg in self.kwargs, (
            'Expected view %s to be called with a URL keyword argument '
            'named "%s". Fix your URL conf, or set the `.lookup_field` '
            'attribute on the view correctly.' %
            (self.__class__.__name__, lookup_url_kwarg)
        )

        filter_kwargs = {self.lookup_field: self.kwargs[lookup_url_kwarg]}
        # obj = get_object_or_404(queryset, **filter_kwargs)
        obj = queryset.filter(**filter_kwargs).first()

        if obj is None:
            raise Http404

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)

        return obj

    def get(self, request, *args, **kwargs):
        self.queryset = self.queryset.filter(is_revoked=False, user=request.user)
        return self.retrieve(request, *args, **kwargs)


class KeyViewP(mixins.CreateModelMixin, mixins.UpdateModelMixin, generics.GenericAPIView):
    queryset = models.Key.objects.all()
    serializer_class = serializers.KeySerializer
    permission_classes = (permissions.IsAuthenticated, )

    def perform_create(self, serializer):
        serializer.save(content_id=self.content_id, is_revoked=False)

    def post(self, request, *args, **kwargs):
        content = get_object_or_404(models.Content.objects.all(), pk=kwargs.get("content_id"))
        if content is None:
            raise Http404

        if request.user != content.owner:
            raise PermissionDenied("You are not the owner")
        self.content_id = int(kwargs.get("content_id", -1))
        return self.create(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)


class KeyViewD(mixins.DestroyModelMixin, generics.GenericAPIView):
    queryset = models.Key.objects.all()
    serializer_class = serializers.KeySerializer
    permission_classes = (permissions.IsAuthenticated, )
    lookup_field = 'content_id'

    def delete(self, request, *args, **kwargs):
        content = get_object_or_404(models.Content.objects.all(), pk=kwargs.get("content_id"))
        if content is None:
            raise Http404

        if request.user != content.owner:
            raise PermissionDenied("You are not the owner")

        self.queryset = self.queryset.filter(user__username=kwargs.pop("username", None))
        return self.destroy(request, *args, **kwargs)