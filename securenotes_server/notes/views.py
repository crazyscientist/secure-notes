from django.db.utils import IntegrityError
from rest_framework import exceptions, generics, mixins, permissions

from notes import models, serializers


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
    queryset = models.Content.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = serializers.ContentSerializer

    def get(self, request, *args, **kwargs):
        self.queryset = self.queryset.filter(aeskey__user=request.user)
        return self.list(request, *args, **kwargs)


class ContentCreateView(mixins.CreateModelMixin, generics.GenericAPIView):
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