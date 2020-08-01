from django.urls import path
from . import views

urlpatterns = [
    path('', views.index),
    path('rdap/help', views.rdap_help),
    path('rdap/domain/<str:term>', views.rdap_domain_lookup),
    path('rdap/entity/<str:term>', views.rdap_entity_lookup),
    path('rdap/nameserver/<str:term>', views.rdap_name_server_lookup),
]
