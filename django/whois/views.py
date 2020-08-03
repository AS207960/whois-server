import grpc
import typing
import json
import datetime
from django.conf import settings
from django.shortcuts import render
from django.utils.safestring import mark_safe
from .whois_grpc import whois_pb2_grpc
from .rdap_grpc import rdap_pb2_grpc, rdap_pb2
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
        query_type = request.POST.get("type")

        try:
            if query_type == "domain":
                term = query_str.encode("idna").decode()
                res = rdap_stub.DomainSearch(rdap_pb2.DomainSearchRequest(
                    name=term
                ))
                res2 = None
            elif query_type == "entity":
                res = rdap_stub.EntitySearch(rdap_pb2.EntitySearchRequest(
                    name=query_str
                ))
                res2 = rdap_stub.EntitySearch(rdap_pb2.EntitySearchRequest(
                    handle=query_str
                ))
            elif query_type == "name_server":
                term = query_str.encode("idna").decode()
                res = rdap_stub.NameServerSearch(rdap_pb2.NameServerSearchRequest(
                    name=term
                ))
                res2 = None
            else:
                res = None
                res2 = None
        except grpc.RpcError as rpc_error:
            error = rpc_error.details()
        else:
            if res:
                if res.WhichOneof("response") == "redirect":
                    http_res = HttpResponse(status=302)
                    http_res["Location"] = res.redirect.rdap_uri
                    return http_res
                elif res.WhichOneof("response") == "error":
                    error = mark_safe(f"{res.error.title}<br>{res.error.description}")
                else:
                    if query_type == "domain":
                        objects = map_domains(res.success.data)
                    elif query_type == "entity":
                        objects = map_entities(res.success.data)
                        objects.extend(map_entities(res2.success.data))
                    elif query_type == "name_server":
                        objects = map_name_servers(res.success.data)

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


def map_js_card_to_jcard(card: rdap_pb2.JSCard):
    elements = [
        ["version", {}, "text", "4.0"],
        ["uid", {}, "text", card.uid],
    ]
    if card.HasField("kind"):
        elements.append(["kind", {}, "text", card.kind.value])
    if card.HasField("full_name"):
        elements.append(["fn", {}, "text", card.full_name.value])
    if card.HasField("updated"):
        elements.append(["rev", {}, "timestamp", card.updated.ToDatetime().isoformat()])
    for online in card.online:
        if online.HasField("type") and online.type.value == "uri":
            if "photo" in online.labels:
                elements.append(["photo", {}, "uri", online.value])
            if "logo" in online.labels:
                elements.append(["logo", {}, "uri", online.value])
            else:
                elements.append(["uri", {}, "uri", online.value])
    for anniversary in card.anniversaries:
        if anniversary.type == "birth":
            elements.append(["bday", {}, "date-time", anniversary.date.ToDatetime().isoformat()])
        elif anniversary.type == "death":
            elements.append(["deathday", {}, "date-time", anniversary.date.ToDatetime().isoformat()])
    for address in card.addresses:
        params = {}
        if address.HasField("full_address"):
            params["label"] = address.full_address.value
        if address.HasField("preferred"):
            params["pref"] = int(address.preferred.value)
        if address.HasField("coordinates"):
            params["geo"] = address.coordinates.value
        if address.HasField("context"):
            params["type"] = address.context.value
        if address.HasField("country_code"):
            params["cc"] = address.country_code.value
        elements.append(["adr", params, "text", [
            address.post_office_box.value if address.HasField("post_office_box") else "",
            address.extension.value if address.HasField("extension") else "",
            address.street.value.split("\n") if address.HasField("street") else "",
            address.locality.value if address.HasField("locality") else "",
            address.region.value if address.HasField("region") else "",
            address.post_code.value if address.HasField("post_code") else "",
            address.country.value if address.HasField("country") else ""
        ]])
    for phone in card.phones:
        params = {}
        if phone.HasField("type"):
            params["type"] = phone.type.value
        if phone.HasField("preferred"):
            params["pref"] = int(phone.preferred.value)
        elements.append(["tel", params, "uri", phone.value])
    for email in card.emails:
        params = {}
        if email.HasField("type"):
            params["type"] = email.type.value
        if email.HasField("preferred"):
            params["pref"] = int(email.preferred.value)
        elements.append(["email", params, "text", email.value])
    for item, value in dict(card.preferred_contact_languages).items():
        for lang in value.languages:
            params = {}
            if lang.HasField("type"):
                params["type"] = lang.type.value
            if lang.HasField("preference"):
                params["pref"] = lang.preference.value
            elements.append(["lang", params, "language-tag", item])
    for job_title in card.job_title:
        elements.append(["title", {}, "text", job_title.value])
    for role in card.role:
        elements.append(["role", {}, "text", role.value])
    for organisation in card.organisation:
        elements.append(["org", {}, "text", organisation.value])
    for personal_info in card.personal_info:
        params = {}
        if personal_info.HasField("level"):
            if personal_info.level.info == "low":
                params["level"] = "beginner"
            elif personal_info.level.info == "medium":
                params["level"] = "average"
            elif personal_info.level.info == "high":
                params["level"] = "expert"
        elements.append([personal_info.type, params, "text", personal_info.value])
    for note in card.notes:
        elements.append(["note", {}, "text", note.value])
    return ["vcard", elements]


def map_js_card(card: rdap_pb2.JSCard):
    def map_localised_string(loc_string: rdap_pb2.JSCard.LocalisedString):
        out = {
            "value": loc_string.value,
            "localizations": dict(loc_string.localisations)
        }
        if loc_string.HasField("language"):
            out["language"] = loc_string.language.value
        return out

    def map_resource(resource: rdap_pb2.JSCard.Resource):
        out = {
            "value": resource.value,
            "labels": {}
        }
        if resource.HasField("context"):
            out["context"] = resource.context.value
        if resource.HasField("type"):
            out["type"] = resource.type.value
        if resource.HasField("media_type"):
            out["mediaType"] = resource.media_type.value
        if resource.HasField("preferred"):
            out["isPreferred"] = resource.preferred.value
        for label in resource.labels:
            out["labels"][label] = True
        return out

    def map_address(address: rdap_pb2.JSCard.Address):
        out = {}
        if address.HasField("context"):
            out["context"] = address.context.value
        if address.HasField("label"):
            out["label"] = address.label.value
        if address.HasField("full_address"):
            out["fullAddress"] = map_localised_string(address.full_address)
        if address.HasField("street"):
            out["street"] = address.street.value
        if address.HasField("extension"):
            out["extension"] = address.extension.value
        if address.HasField("locality"):
            out["locality"] = address.locality.value
        if address.HasField("region"):
            out["region"] = address.region.value
        if address.HasField("country"):
            out["country"] = address.country.value
        if address.HasField("post_office_box"):
            out["postOfficeBox"] = address.post_office_box.value
        if address.HasField("post_code"):
            out["postcode"] = address.post_code.value
        if address.HasField("country_code"):
            out["countryCode"] = address.country_code.value
        if address.HasField("coordinates"):
            out["coordinates"] = address.coordinates.value
        if address.HasField("timezone"):
            out["timeZone"] = address.timezone.value
        if address.HasField("preferred"):
            out["isPreferred"] = address.preferred.value
        return out

    def map_anniversary(anniversary: rdap_pb2.JSCard.Anniversary):
        out = {
            "type": anniversary.type,
        }
        if anniversary.HasField("label"):
            out["label"] = anniversary.label.value
        if anniversary.HasField("date"):
            out["date"] = anniversary.date.ToDatetime().date().isoformat()
        if anniversary.HasField("place"):
            out["place"] = map_address(anniversary.place)
        return out

    def map_personal_info(personal_info: rdap_pb2.JSCard.PersonalInfo):
        out = {
            "type": personal_info.type,
            "value": personal_info.value
        }
        if personal_info.HasField("level"):
            out["level"] = personal_info.level.value
        return out

    card_dict = {
        "uid": card.uid,
        "organization": list(map(map_localised_string, card.organisation)),
        "jobTitle": list(map(map_localised_string, card.job_title)),
        "role": list(map(map_localised_string, card.role)),
        "emails": list(map(map_resource, card.emails)),
        "phones": list(map(map_resource, card.phones)),
        "online": list(map(map_resource, card.online)),
        "preferredContactLanguages": {},
        "addresses": list(map(map_address, card.addresses)),
        "anniversaries": list(map(map_anniversary, card.anniversaries)),
        "personalInfo": list(map(map_personal_info, card.personal_info)),
        "notes": list(map(map_localised_string, card.notes)),
        "categories": list(card.categories),
    }
    if card.HasField("updated"):
        card_dict["upated"] = card.updated.ToDatetime().isoformat()
    if card.HasField("kind"):
        card_dict["kind"] = card.kind.value
    if card.HasField("full_name"):
        card_dict["fullName"] = map_localised_string(card.full_name)
    if card.HasField("preferred_contact_method"):
        card_dict["preferredContactMethod"] = card.preferred_contact_method.value
    for item, value in dict(card.preferred_contact_languages).items():
        l_array = []
        for language in value.languages:
            l_dict = {}
            if language.HasField("type"):
                l_dict["type"] = language.type.value
            if language.HasField("preference"):
                l_dict["preference"] = language.preference.value
            l_array.append(l_dict)
        card_dict["preferredContactLanguages"]["item"] = l_array

    return card_dict


def map_entity(entity: rdap_pb2.Entity) -> dict:
    out = {
        "objectClassName": "entity",
        "handle": entity.handle,
        "roles": map_roles(entity.roles),
        "publicIds": map_public_ids(entity.public_ids),
        "entities": map_entities(entity.entities),
        "status": map_statuses(entity.statuses),
        "remarks": map_remarks(entity.remarks),
    }
    if entity.HasField("js_card"):
        out["vcardArray"] = map_js_card_to_jcard(entity.js_card)
        out["jscard"] = map_js_card(entity.js_card)
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


def map_domains(domains: typing.Iterable[rdap_pb2.Domain]) -> typing.List[dict]:
    return list(map(map_domain, domains))


def make_rdap_response(data, status):
    data["rdapConformance"] = [
        "rdap_level_0",
        "icann_rdap_response_profile_0",
        "icann_rdap_technical_implementation_guide_0",
        "jscard"
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
            "href": "https://icann.org/epp",
            "title": "More information on domain status codes"
        }
    }, {
        "title": "RDDS Inaccuracy Complaint Form",
        "description": [
            "URL of the ICANN RDDS Inaccuracy Complaint Form: https://icann.org/wicf"
        ],
        "links": {
            "href": "https://icann.org/wicf",
            "title": "ICANN RDDS Inaccuracy Complaint Form"
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
    http_res["Access-Control-Allow-Origin"] = "*"
    return http_res


def rdap_help(request):
    return make_rdap_response({
        "notices": [{
            "title": "RDAP Help",
            "description": [
                "domain/XXXX",
                "nameserver/XXXX",
                "entity/XXXX",
                "domains?name=XXXX",
                "domains?nsLdhName=XXXX",
                "domains?nsIp=XXXX",
                "nameservers?name=XXXX",
                "nameservers?ip=XXXX",
                "entities?fn=XXXX",
                "entities?handle=XXXX",
                "help",
            ],
            "links": {
                "href": "https://whois-web.as207960.net"
            }
        }]
    }, 200)


def rdap_domain_lookup(request, term):
    term = term.encode("idna").decode()
    res = rdap_stub.DomainLookup(rdap_pb2.LookupRequest(
        query=term
    ))
    if res.WhichOneof("response") == "redirect":
        http_res = HttpResponse(status=302)
        http_res["Location"] = res.redirect.rdap_uri
        http_res["Access-Control-Allow-Origin"] = "*"
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


def rdap_domain_search(request):
    query = rdap_pb2.DomainSearchRequest()
    if "name" in request.GET:
        query.name = request.GET["name"].encode("idna").decode()
    elif "nsLdhName" in request.GET:
        query.ns_name = request.GET["nsLdhName"]
    elif "nsIp" in request.GET:
        query.ns_ip = request.GET["nsIp"]
    else:
        return make_rdap_response({
            "errorCode": 400,
            "title": "Bad request",
            "description": "Unknown query parameter"
        }, 400)

    res = rdap_stub.DomainSearch(query)
    if res.WhichOneof("response") == "redirect":
        http_res = HttpResponse(status=302)
        http_res["Location"] = res.redirect.rdap_uri
        http_res["Access-Control-Allow-Origin"] = "*"
        return http_res
    elif res.WhichOneof("response") == "error":
        data = {
            "errorCode": res.error.error_code,
            "title": res.error.title,
            "description": res.error.description.split("\n")
        }
        status = res.error.error_code
    else:
        data = {
            "domainSearchResults": map_domains(res.success.data)
        }
        status = 200

    return make_rdap_response(data, status)


def rdap_entity_lookup(request, term):
    res = rdap_stub.EntityLookup(rdap_pb2.LookupRequest(
        query=term
    ))
    if res.WhichOneof("response") == "redirect":
        http_res = HttpResponse(status=302)
        http_res["Location"] = res.redirect.rdap_uri
        http_res["Access-Control-Allow-Origin"] = "*"
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


def rdap_entity_search(request):
    query = rdap_pb2.EntitySearchRequest()
    if "fn" in request.GET:
        query.name = request.GET["fn"]
    elif "handle" in request.GET:
        query.handle = request.GET["handle"]
    else:
        return make_rdap_response({
            "errorCode": 400,
            "title": "Bad request",
            "description": "Unknown query parameter"
        }, 400)

    res = rdap_stub.EntitySearch(query)
    if res.WhichOneof("response") == "redirect":
        http_res = HttpResponse(status=302)
        http_res["Location"] = res.redirect.rdap_uri
        http_res["Access-Control-Allow-Origin"] = "*"
        return http_res
    elif res.WhichOneof("response") == "error":
        data = {
            "errorCode": res.error.error_code,
            "title": res.error.title,
            "description": res.error.description.split("\n")
        }
        status = res.error.error_code
    else:
        data = {
            "entitySearchResults": map_entities(res.success.data)
        }
        status = 200

    return make_rdap_response(data, status)


def rdap_name_server_lookup(request, term):
    term = term.encode("idna").decode()
    res = rdap_stub.NameServerLookup(rdap_pb2.LookupRequest(
        query=term
    ))
    if res.WhichOneof("response") == "redirect":
        http_res = HttpResponse(status=302)
        http_res["Location"] = res.redirect.rdap_uri
        http_res["Access-Control-Allow-Origin"] = "*"
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


def rdap_name_server_search(request):
    query = rdap_pb2.NameServerSearchRequest()
    if "name" in request.GET:
        query.name = request.GET["name"].encode("idna").decode()
    elif "ip" in request.GET:
        query.ip = request.GET["ip"]
    else:
        return make_rdap_response({
            "errorCode": 400,
            "title": "Bad request",
            "description": "Unknown query parameter"
        }, 400)

    res = rdap_stub.NameServerSearch(query)
    if res.WhichOneof("response") == "redirect":
        http_res = HttpResponse(status=302)
        http_res["Location"] = res.redirect.rdap_uri
        http_res["Access-Control-Allow-Origin"] = "*"
        return http_res
    elif res.WhichOneof("response") == "error":
        data = {
            "errorCode": res.error.error_code,
            "title": res.error.title,
            "description": res.error.description.split("\n")
        }
        status = res.error.error_code
    else:
        data = {
            "nameserverSearchResults": map_name_servers(res.success.data)
        }
        status = 200

    return make_rdap_response(data, status)
