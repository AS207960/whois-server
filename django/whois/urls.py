from django.urls import path
from . import views

urlpatterns = [
    path('', views.index),
    path('rdap/help', views.rdap_help),
    path('rdap/domain/<str:term>', views.rdap_domain_lookup),
    path('rdap/domains', views.rdap_domain_search),
    path('rdap/entity/<str:term>', views.rdap_entity_lookup),
    path('rdap/entities', views.rdap_entity_search),
    path('rdap/nameserver/<str:term>', views.rdap_name_server_lookup),
    path('rdap/nameservers', views.rdap_name_server_search),
]
