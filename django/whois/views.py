import grpc
from django.conf import settings
from django.shortcuts import render
from .whois_grpc import whois_pb2_grpc, whois_pb2
from django.core.validators import URLValidator, EmailValidator
from django.core.exceptions import ValidationError

channel = grpc.insecure_channel(settings.WHOIS_ADDR)
stub = whois_pb2_grpc.WHOISStub(channel)


def index(request):
    error = None
    objects = None
    if request.method == "POST":
        query_str = request.POST.get("query")

        try:
            res = stub.WHOISQuery(whois_pb2.WHOISRequest(
                query=query_str
            ))
            url_val = URLValidator()
            email_val = EmailValidator()
            objects = []
            for obj in res.objects:
                object_data = []
                for element in obj.elements:
                    elm = {
                        "key": element.key,
                        "value": element.value
                    }
                    try:
                        url_val(element.value.strip())
                        elm["is_url"] = True
                    except ValidationError:
                        try:
                            email_val(element.value.strip())
                            elm["is_email"] = True
                        except ValidationError:
                            pass
                    object_data.append(elm)
                objects.append(object_data)

        except grpc.RpcError as rpc_error:
            error = rpc_error.details()

    return render(request, "whois/search.html", {
        "error": error,
        "objects": objects
    })
