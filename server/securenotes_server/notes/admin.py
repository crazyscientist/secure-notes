from django.contrib import admin
from notes import models


# Register your models here.
class CryptoAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_revoked')
    list_filter = ('user', 'is_revoked')


class ContentAdmin(admin.ModelAdmin):
    list_display = ('owner', 'title')
    list_filter = ('owner', 'title')


class KeyAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_revoked', )
    list_filter = ('user', 'is_revoked',)


admin.site.register(models.CryptoKey, CryptoAdmin)
admin.site.register(models.Content, ContentAdmin)
admin.site.register(models.Key, KeyAdmin)