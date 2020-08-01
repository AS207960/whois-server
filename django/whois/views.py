import grpc
import typing
import json
import datetime
from django.conf import settings
from django.shortcuts import render
from django.utils.safestring import mark_safe
from .whois_grpc import whois_pb2_grpc, whois_pb2
from .rdap_grpc import rdap_pb2_grpc, rdap_pb2
from django.core.validators import URLValidator, EmailValidator
from django.core.exceptions import ValidationError
from django.http import HttpResponse

channel = grpc.insecure_channel(settings.WHOIS_ADDR)
stub = whois_pb2_grpc.WHOISStub(channel)
rdap_stub = rdap_pb2_grpc.RDAPStub(channel)


def index(request):
    error = None
    objects = None
    redirect = None
    if request.method == "POST":
        query_str = request.POST.get("query")

        term = query_str.encode().decode("idna")

        try:
            res = rdap_stub.DomainLookup(rdap_pb2.LookupRequest(
                query=term
            ))
        except grpc.RpcError as rpc_error:
            error = rpc_error.details()
        else:
            if res.WhichOneof("response") == "redirect":
                http_res = HttpResponse(status=302)
                http_res["Location"] = res.redirect.rdap_uri
                return http_res
            elif res.WhichOneof("response") == "error":
                error = mark_safe(f"{res.error.title}<br>{res.error.description}")
            else:
                objects = [map_domain(res.success)]

    return render(request, "whois/search.html", {
        "error": error,
        "objects": objects,
        "redirect": redirect
    })


def map_event(event: rdap_pb2.Event) -> dict:
    out = {}
    if event.action == rdap_pb2.EventRegistration:
        out["eventAction"] = "registration"
    elif event.action == rdap_pb2.EventReregistration:
        out["eventAction"] = "reregistration"
    elif event.action == rdap_pb2.EventLastChanged:
        out["eventAction"] = "last changed"
    elif event.action == rdap_pb2.EventExpiration:
        out["eventAction"] = "expiration"
    elif event.action == rdap_pb2.EventDeletion:
        out["eventAction"] = "deletion"
    elif event.action == rdap_pb2.EventReinstantiation:
        out["eventAction"] = "reinstatiation"
    elif event.action == rdap_pb2.EventTransfer:
        out["eventAction"] = "transfer"
    elif event.action == rdap_pb2.EventLocked:
        out["eventAction"] = "locked"
    elif event.action == rdap_pb2.EventUnlocked:
        out["eventAction"] = "unlocked"
    elif event.action == rdap_pb2.EventRegistrarExpiration:
        out["eventAction"] = "registrar expiration"
    elif event.action == rdap_pb2.EventLastUpdateOfRDAP:
        out["eventAction"] = "last update of RDAP database"
    if event.HasField("date"):
        out["eventDate"] = event.date.ToDatetime().replace(tzinfo=datetime.timezone.utc).isoformat()
    if event.HasField("actor"):
        out["eventActor"] = event.actor.value
    return out


def map_events(events: typing.Iterable) -> typing.List[dict]:
    return list(map(map_event, events))


def map_role(role: rdap_pb2.EntityRole) -> str:
    if role == rdap_pb2.RoleRegistrant:
        return "registrant"
    elif role == rdap_pb2.RoleTechnical:
        return "technical"
    elif role == rdap_pb2.RoleAdministrative:
        return "administrative"
    elif role == rdap_pb2.RoleAbuse:
        return "abuse"
    elif role == rdap_pb2.RoleBilling:
        return "billing"
    elif role == rdap_pb2.RoleRegistrar:
        return "registrar"
    elif role == rdap_pb2.RoleReseller:
        return "reseller"
    elif role == rdap_pb2.RoleSponsor:
        return "sponsor"
    elif role == rdap_pb2.RoleProxy:
        return "proxy"
    elif role == rdap_pb2.RoleNotifications:
        return "notifications"
    elif role == rdap_pb2.RoleNOC:
        return "noc"


def map_roles(roles: typing.Iterable) -> typing.List[str]:
    return list(map(map_role, roles))


def map_status(status: rdap_pb2.Status) -> str:
    if status == rdap_pb2.StatusActive:
        return "active"
    elif status == rdap_pb2.StatusInactive:
        return "inactive"
    elif status == rdap_pb2.StatusValidated:
        return "validated"
    elif status == rdap_pb2.StatusRenewProhibited:
        return "renew prohibited"
    elif status == rdap_pb2.StatusUpdateProhibited:
        return "update prohibited"
    elif status == rdap_pb2.StatusTransferProhibited:
        return "transfer prohibited"
    elif status == rdap_pb2.StatusDeleteProhibited:
        return "delete prohibited"
    elif status == rdap_pb2.StatusProxy:
        return "proxy"
    elif status == rdap_pb2.StatusPrivate:
        return "private"
    elif status == rdap_pb2.StatusRemoved:
        return "removed"
    elif status == rdap_pb2.StatusObscured:
        return "obscured"
    elif status == rdap_pb2.StatusAssociated:
        return "associated"
    elif status == rdap_pb2.StatusLocked:
        return "locked"
    elif status == rdap_pb2.StatusPendingCreate:
        return "pending create"
    elif status == rdap_pb2.StatusPendingRenew:
        return "pending renew"
    elif status == rdap_pb2.StatusPendingTransfer:
        return "pending transfer"
    elif status == rdap_pb2.StatusPendingUpdate:
        return "pending update"
    elif status == rdap_pb2.StatusPendingDelete:
        return "pending delete"
    elif status == rdap_pb2.StatusPendingRestore:
        return "pending restore"
    elif status == rdap_pb2.StatusAddPeriod:
        return "add period"
    elif status == rdap_pb2.StatusAutoRenewPeriod:
        return "auto renew period"
    elif status == rdap_pb2.StatusRedemptionPeriod:
        return "redemption period"
    elif status == rdap_pb2.StatusRenewPeriod:
        return "renew period"
    elif status == rdap_pb2.StatusTransferPeriod:
        return "transfer period"
    elif status == rdap_pb2.StatusClientRenewProhibited:
        return "client renew prohibited"
    elif status == rdap_pb2.StatusClientUpdateProhibited:
        return "client update prohibited"
    elif status == rdap_pb2.StatusClientTransferProhibited:
        return "client transfer prohibited"
    elif status == rdap_pb2.StatusClientDeleteProhibited:
        return "client delete prohibited"
    elif status == rdap_pb2.StatusClientHold:
        return "client hold"
    elif status == rdap_pb2.StatusServerRenewProhibited:
        return "server renew prohibited"
    elif status == rdap_pb2.StatusServerUpdateProhibited:
        return "server update prohibited"
    elif status == rdap_pb2.StatusServerTransferProhibited:
        return "server transfer prohibited"
    elif status == rdap_pb2.StatusServerDeleteProhibited:
        return "server delete prohibited"
    elif status == rdap_pb2.StatusServerHold:
        return "server hold"


def map_statuses(roles: typing.Iterable) -> typing.List[str]:
    return list(map(map_status, roles))


def map_public_id(public_id: rdap_pb2.PublicID) -> dict:
    return {
        "type": public_id.type,
        "identifier": public_id.identifier
    }


def map_public_ids(public_ids: typing.Iterable[rdap_pb2.PublicID]) -> typing.List[dict]:
    return list(map(map_public_id, public_ids))


def map_remark(remark: rdap_pb2.Remark) -> dict:
    out = {
        "description": remark.description.split("\n")
    }
    if remark.HasField("title"):
        out["title"] = remark.title.value
    if remark.HasField("type"):
        out["type"] = remark.type.value
    return out


def map_remarks(remarks: typing.Iterable[rdap_pb2.Remark]) -> typing.List[dict]:
    return list(map(map_remark, remarks))


def map_card(card: rdap_pb2.jCard):
    elements = [
        ["version", {}, "text", "4.0"]
    ]
    for element in card.properties:
        if element.WhichOneof("value") == "text":
            e_type = "text"
            e_value = element.text
        elif element.WhichOneof("value") == "uri":
            e_type = "uri"
            e_value = element.uri
        elif element.WhichOneof("value") == "text_array":
            e_type = "text"
            e_value = list(element.text_array.data)
        elif element.WhichOneof("value") == "date":
            e_type = "date"
            e_value = element.date.ToDatetime().date().isoformat()
        elif element.WhichOneof("value") == "time":
            e_type = "time"
            e_value = element.time.ToDatetime().time().isoformat()
        elif element.WhichOneof("value") == "date_time":
            e_type = "date-time"
            e_value = element.date_time.ToDatetime().isoformat()
        elif element.WhichOneof("value") == "timestamp":
            e_type = "timestamp"
            e_value = element.timestamp.ToDatetime().isoformat()
        elif element.WhichOneof("value") == "boolean":
            e_type = "boolean"
            e_value = element.boolean
        elif element.WhichOneof("value") == "integer":
            e_type = "integer"
            e_value = element.integer
        elif element.WhichOneof("value") == "float":
            e_type = "float"
            e_value = element.float
        elif element.WhichOneof("value") == "language":
            e_type = "language-tag"
            e_value = element.language
        else:
            e_type = element.extension.type
            e_value = element.extension.value

        elements.append([
            element.name,
            dict(element.properties),
            e_type,
            e_value
        ])
    return ["vcard", elements]


def map_entity(entity: rdap_pb2.Entity) -> dict:
    out = {
        "objectClassName": "entity",
        "handle": entity.handle,
        "roles": map_roles(entity.roles),
        "publicIds": map_public_ids(entity.public_ids),
        "entities": map_entities(entity.entities),
        "status": map_statuses(entity.statuses),
        "remarks": map_remarks(entity.remarks),
        "vcardArray": map_card(entity.card),
    }
    if entity.HasField("port43"):
        out["port43"] = entity.port43.value
    return out


def map_entities(entities: typing.Iterable[rdap_pb2.Entity]) -> typing.List[dict]:
    return list(map(map_entity, entities))


def map_name_server(name_server: rdap_pb2.NameServer) -> dict:
    out = {
        "objectClassName": "nameserver",
        "handle": name_server.handle,
        "ldhName": name_server.name,
        "unicodeName": name_server.name.encode().decode("idna"),
        "events": map_events(name_server.events),
        "entities": map_entities(name_server.entities),
        "status": map_statuses(name_server.statuses),
        "remarks": map_remarks(name_server.remarks),
    }
    if name_server.HasField("ip_addresses"):
        out["ipAddresses"] = {
            "v4": name_server.ip_addresses.v4,
            "v6": name_server.ip_addresses.v6
        }
    if name_server.HasField("port43"):
        out["port43"] = name_server.port43.value
    return out


def map_name_servers(name_servers: typing.Iterable[rdap_pb2.NameServer]) -> typing.List[dict]:
    return list(map(map_name_server, name_servers))


def map_domain(domain: rdap_pb2.Domain) -> dict:
    out = {
        "objectClassName": "domain",
        "handle": domain.handle,
        "ldhName": domain.name,
        "unicodeName": domain.name.encode().decode("idna"),
        "events": map_events(domain.events),
        "entities": map_entities(domain.entities),
        "status": map_statuses(domain.statuses),
        "remarks": map_remarks(domain.remarks),
        "publicIds": map_public_ids(domain.public_ids),
        "nameservers": map_name_servers(domain.name_servers)
    }
    if domain.HasField("port43"):
        out["port43"] = domain.port43.value
    if domain.HasField("sec_dns"):
        secure_dns = {}
        if domain.sec_dns.HasField("zone_signed"):
            secure_dns["zoneSigned"] = domain.sec_dns.zone_signed.value
        if domain.sec_dns.HasField("delegation_signed"):
            secure_dns["delegationSigned"] = domain.sec_dns.delegation_signed.value
        if domain.sec_dns.HasField("max_sig_life"):
            secure_dns["maxSigLife"] = domain.sec_dns.max_sig_life.value
        secure_dns["dsData"] = list(map(lambda d: {
            "keyTag": d.key_tag,
            "algorithm": d.algorithm,
            "digestType": d.digest_type,
            "digest": d.digest
        }, domain.sec_dns.ds_data))
        secure_dns["keyData"] = list(map(lambda d: {
            "flags": d.flags,
            "protocol": d.protocol,
            "algorithm": d.algorithm,
            "publicKey": d.public_key,
        }, domain.sec_dns.key_data))
        out["secureDNS"] = secure_dns
    return out


def make_rdap_response(data, status):
    data["rdapConformance"] = [
        "rdap_level_0",
        "icann_rdap_response_profile_0",
        "icann_rdap_technical_implementation_guide_0"
    ]
    data["lang"] = "en"
    if "notices" not in data:
        data["notices"] = []
    data["notices"].extend([{
        "title": "Status codes",
        "description": [
            "For more information on domain status codes, please visit https://icann.org/epp"
        ],
        "links": {
            "href": "https://icann.org/epp"
        }
    }, {
        "title": "RDDS Inaccuracy Complaint Form",
        "description": [
            "URL of the ICANN RDDS Inaccuracy Complaint Form: https://icann.org/wicf"
        ],
        "links": {
            "href": "https://icann.org/wicf"
        }
    }, {
        "title": "Terms of Use",
        "description": [
            "You may use this service for any lawful purpose except to allow, enable, or "
            "otherwise support the transmission by e-mail, telephone, or facsimile of mass, unsolicited "
            "commercial advertising or solicitations to entities or to enable high volume, automated, "
            "electronic processes that send queries to our systems or the systems of any Registry Operator. "
            "Access to the WHOIS database is provided solely to obtain information about or related to a "
            "domain name registration record, and no warranty is made as to its accuracy or fitness for any "
            "particular purpose. We reserve the right to restrict your access to the WHOIS database at our sole "
            "discretion to ensure operational stability and restrict abuse."
        ]
    }, {
        "title": "Trans Rights",
        "description": [
            "\x1b[38;5;81m████████ ██████   █████  ███    ██ ███████\x1b[0m",
            "\x1b[38;5;81m   ██    ██   ██ ██   ██ ████   ██ ██     \x1b[0m",
            "\x1b[38;5;218m   ██    ██████  ███████ ██ ██  ██ ███████\x1b[0m",
            "\x1b[38;5;218m   ██    ██   ██ ██   ██ ██  ██ ██      ██\x1b[0m",
            "\x1b[38;5;231m   ██    ██   ██ ██   ██ ██   ████ ███████\x1b[0m",
            "                                            ",
            "\x1b[38;5;231m██████  ██  ██████  ██   ██ ████████ ███████\x1b[0m",
            "\x1b[38;5;218m██   ██ ██ ██       ██   ██    ██    ██     \x1b[0m",
            "\x1b[38;5;218m██████  ██ ██   ███ ███████    ██    ███████\x1b[0m",
            "\x1b[38;5;81m██   ██ ██ ██    ██ ██   ██    ██         ██\x1b[0m",
            "\x1b[38;5;81m██   ██ ██  ██████  ██   ██    ██    ███████\x1b[0m",
        ]
    }])
    http_res = HttpResponse(json.dumps(data), status=status, content_type="application/rdap+json")
    return http_res


def rdap_help(request):
    return make_rdap_response({
        "notices": [{
            "title": "RDAP Help",
            "description": [
                "domain/XXXX",
                "nameserver/XXXX",
                "entity/XXXX",
            ]
        }]
    }, 200)


def rdap_domain_lookup(request, term):
    term = term.encode().decode("idna")
    res = rdap_stub.DomainLookup(rdap_pb2.LookupRequest(
        query=term
    ))
    if res.WhichOneof("response") == "redirect":
        http_res = HttpResponse(status=302)
        http_res["Location"] = res.redirect.rdap_uri
        return http_res
    elif res.WhichOneof("response") == "error":
        data = {
            "errorCode": res.error.error_code,
            "title": res.error.title,
            "description": res.error.description.split("\n")
        }
        status = res.error.error_code
    else:
        data = map_domain(res.success)
        status = 200

    return make_rdap_response(data, status)


def rdap_entity_lookup(request, term):
    res = rdap_stub.EntityLookup(rdap_pb2.LookupRequest(
        query=term
    ))
    if res.WhichOneof("response") == "redirect":
        http_res = HttpResponse(status=302)
        http_res["Location"] = res.redirect.rdap_uri
        return http_res
    elif res.WhichOneof("response") == "error":
        data = {
            "errorCode": res.error.error_code,
            "title": res.error.title,
            "description": res.error.description.split("\n")
        }
        status = res.error.error_code
    else:
        data = map_entity(res.success)
        status = 200

    return make_rdap_response(data, status)


def rdap_name_server_lookup(request, term):
    term = term.encode().decode("idna")
    res = rdap_stub.NameServerLookup(rdap_pb2.LookupRequest(
        query=term
    ))
    if res.WhichOneof("response") == "redirect":
        http_res = HttpResponse(status=302)
        http_res["Location"] = res.redirect.rdap_uri
        return http_res
    elif res.WhichOneof("response") == "error":
        data = {
            "errorCode": res.error.error_code,
            "title": res.error.title,
            "description": res.error.description.split("\n")
        }
        status = res.error.error_code
    else:
        data = map_name_server(res.success)
        status = 200

    return make_rdap_response(data, status)
