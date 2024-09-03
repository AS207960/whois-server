import grpc
import typing
import json
import datetime
from django.conf import settings
from django.shortcuts import render
from django.utils.safestring import mark_safe
from .rdap_grpc import rdap_pb2_grpc, rdap_pb2
from django.http import HttpResponse

channel = grpc.insecure_channel(settings.WHOIS_ADDR)
rdap_stub = rdap_pb2_grpc.RDAPStub(channel)


def index(request):
    error = None
    objects = None
    redirect = None
    if request.method == "POST":
        query_str = request.POST.get("query")
        query_type = request.POST.get("type")

        if query_str:
            try:
                print(query_type, query_str)
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

    if card.kind == rdap_pb2.JSCard.Individual:
        elements.append(["kind", {}, "text", "individual"])
    elif card.kind == rdap_pb2.JSCard.Group:
        elements.append(["kind", {}, "text", "group"])
    elif card.kind == rdap_pb2.JSCard.Org:
        elements.append(["kind", {}, "text", "org"])
    elif card.kind == rdap_pb2.JSCard.Location:
        elements.append(["kind", {}, "text", "location"])
    elif card.kind == rdap_pb2.JSCard.Application:
        elements.append(["kind", {}, "text", "application"])
    elif card.kind == rdap_pb2.JSCard.Device:
        elements.append(["kind", {}, "text", "device"])

    if card.HasField("product_id"):
        elements.append(["prodid", {}, "text", card.product_id.value])

    if card.HasField("name"):
        if card.name.HasField("full_name"):
            elements.append(["fn", {}, "text", card.name.full_name.value])

        surname = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Name.NameComponent.Surname,
            card.name.components
        )) + list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Name.NameComponent.Surname2,
            card.name.components
        ))
        given = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Name.NameComponent.Given,
            card.name.components
        ))
        additional = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Name.NameComponent.Middle,
            card.name.components
        ))
        hon_pre = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Name.NameComponent.Title,
            card.name.components
        ))
        hon_suf = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Name.NameComponent.Generation,
            card.name.components
        )) + list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Name.NameComponent.Credential,
            card.name.components
        ))

        if surname or given or additional or hon_pre or hon_suf:
            surname = ','.join([c.value for c in surname])
            given = ','.join([c.value for c in given])
            additional = ','.join([c.value for c in additional])
            hon_pre = ','.join([c.value for c in hon_pre])
            hon_suf = ','.join([c.value for c in hon_suf])
            elements.append(["n", {}, "text", f"{surname};{given};{additional};{hon_pre};{hon_suf}"])

    if len(card.nick_names):
        nn = ','.join([n.name for n in card.nick_names])
        elements.append(["nickname", {}, "text", nn])

    for org in card.organisations.values():
        if org.name:
            units = ';'.join([org.name.value] + [u.name for u in org.units])
            elements.append(["org", {}, "text", units])

    for title in card.titles.values():
        if title.kind == rdap_pb2.JSCard.Title.Role:
            elements.append(["role", {}, "text", title.name])
        else:
            elements.append(["title", {}, "text", title.name])

    for email in card.emails.values():
        elements.append(["email", {}, "text", email.email])

    for os in card.online_services.values():
        if os.HasField("uri"):
            elements.append(["url", {}, "uri", os.uri.value])

    for phone in card.phones.values():
        attr = {}
        for f in phone.features:
            if f == rdap_pb2.JSCard.Phone.Mobile:
                t = "cell"
            elif f == rdap_pb2.JSCard.Phone.Voice:
                t = "voice"
            elif f == rdap_pb2.JSCard.Phone.Text:
                t = "text"
            elif f == rdap_pb2.JSCard.Phone.Video:
                t = "video"
            elif f == rdap_pb2.JSCard.Phone.MainNumber:
                continue
            elif f == rdap_pb2.JSCard.Phone.Textphone:
                t = "textphone"
            elif f == rdap_pb2.JSCard.Phone.Fax:
                t = "fax"
            elif f == rdap_pb2.JSCard.Phone.Pager:
                t = "pager"
            else:
                continue

            if "type" in attr:
                attr["type"].append(t)
            else:
                attr["type"] = [t]

        elements.append(["tel", attr, "text", phone.number])

    for lang in card.preferred_languages.keys():
        elements.append(["lang", {}, "language-tag", lang])

    for cal in card.calendars.values():
        attr = {}
        if cal.kind == rdap_pb2.JSCard.Calendar.Calendar:
            t = "caluri"
        elif cal.kind == rdap_pb2.JSCard.Calendar.FreeBusy:
            t = "fburi"
        else:
            continue

        if cal.resource.HasField("media_type"):
            attr["mediatype"] = cal.resource.media_type.value

        elements.append([t, attr, "uri", cal.resource.uri])

    for sa in card.scheduling_addresses.values():
        elements.append(["caladruri", {}, "uri", sa.uri])

    for a in card.addresses.values():
        attr = {}
        if a.HasField("timezone"):
            attr["tz"] = a.timezone.value
        if a.HasField("coordinates"):
            attr["geo"] = a.coordinates.value

        post_office_box = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.PostOfficeBox,
            a.components,
        ))
        extended_address = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Room,
            a.components,
        )) + list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Apartment,
            a.components,
        )) + list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Floor,
            a.components,
        )) + list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Building,
            a.components,
        ))
        street_address = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Number,
            a.components,
        )) + list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Name,
            a.components,
        )) + list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Block,
            a.components,
        ))
        locality = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Locality,
            a.components,
        ))
        region = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Region,
            a.components,
        ))
        postal_code = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Postcode,
            a.components,
        ))
        country = list(filter(
            lambda c: c.kind == rdap_pb2.JSCard.Address.AddressComponent.Country,
            a.components,
        ))

        post_office_box = ",".join([c.value for c in post_office_box])
        extended_address = ",".join([c.value for c in extended_address])
        street_address = ",".join([c.value for c in street_address])
        locality = ",".join([c.value for c in locality])
        region = ",".join([c.value for c in region])
        postal_code = ",".join([c.value for c in postal_code])
        country = ",".join([c.value for c in country])

        elements.append(["adr", attr, "text", ";".join([
            post_office_box, extended_address, street_address, locality,
            region, postal_code, country
        ])])

    for k in card.crypto_keys.values():
        attr = {}
        if k.HasField("media_type"):
            attr["mediatype"] = k.media_type.value
        elements.append(["key", attr, "uri", k.uri])

    for link in card.links.values():
        attr = {}
        if link.resource.HasField("media_type"):
            attr["mediatype"] = link.resource.media_type.value
        elements.append(["url", attr, "uri", link.resource.uri])

    for media in card.media.values():
        if media.kind == rdap_pb2.JSCard.Media.Logo:
            t = "logo"
        elif media.kind == rdap_pb2.JSCard.Media.Photo:
            t = "photo"
        elif media.kind == rdap_pb2.JSCard.Media.Sound:
            t = "sound"
        else:
            continue

        attr = {}
        if media.resource.HasField("media_type"):
            attr["mediatype"] = media.resource.media_type.value
        elements.append([t, attr, "uri", media.resource.uri])

    for note in card.notes.values():
        elements.append(["note", {}, "text", note.note])

    return ["vcard", elements]


def map_js_card(card: rdap_pb2.JSCard):
    def map_pronounce(pronounce: rdap_pb2.JSCard.Pronounce) -> dict:
        obj = {
            "@type": "Pronounce",
            "phonetics": pronounce.phonetics,
        }
        if pronounce.HasField("script"):
            obj["script"] = pronounce.script.value
        if pronounce.HasField("system"):
            obj["system"] = pronounce.system.value
        return obj

    def map_context(context: rdap_pb2.JSCard.Context) -> dict:
        obj = {}

        if context.private:
            obj["private"] = True
        if context.work:
            obj["work"] = True
        if context.billing:
            obj["billing"] = True
        if context.delivery:
            obj["delivery"] = True

        return obj

    def map_name_component(component: rdap_pb2.JSCard.Name.NameComponent) -> dict:
        if component.kind == rdap_pb2.JSCard.Name.NameComponent.Title:
            k = "title"
        elif component.kind == rdap_pb2.JSCard.Name.NameComponent.Given:
            k = "given"
        elif component.kind == rdap_pb2.JSCard.Name.NameComponent.Surname:
            k = "surname"
        elif component.kind == rdap_pb2.JSCard.Name.NameComponent.Surname2:
            k = "surname2"
        elif component.kind == rdap_pb2.JSCard.Name.NameComponent.Middle:
            k = "middle"
        elif component.kind == rdap_pb2.JSCard.Name.NameComponent.Credential:
            k = "credential"
        elif component.kind == rdap_pb2.JSCard.Name.NameComponent.Generation:
            k = "generation"
        elif component.kind == rdap_pb2.JSCard.Name.NameComponent.Separator:
            k = "seperator"
        else:
            k = ""

        obj = {
            "@type": "NameComponent",
            "value": component.value,
            "kind": k,
        }
        if component.HasField("pronounce"):
            obj["pronounce"] = map_pronounce(component.pronounce)
        return obj

    def map_org_unit(unit: rdap_pb2.JSCard.Organisation.OrganisationUnit) -> dict:
        obj = {
            "@type": "OrgUnit",
            "name": unit.name,
        }
        if unit.HasField("sort_as"):
            obj["sortAs"] = unit.sort_as.value
        return obj

    def map_language_pref(pref: rdap_pb2.JSCard.LanguagePreferences.LanguagePreference) -> dict:
        obj = {
            "@type": "LanguagePref"
        }
        if v.HasField("context"):
            obj["contexts"] = map_context(v.context)
        if v.HasField("preference"):
            obj["pref"] = v.preference.value
        return obj

    def map_resource(res: rdap_pb2.JSCard.Resource) -> dict:
        obj = {
            "uri": res.uri,
        }
        if res.HasField("media_type"):
            obj["mediaType"] = res.media_type.value
        if res.HasField("context"):
            obj["contexts"] = map_context(res.context)
        if res.HasField("preference"):
            obj["pref"] = res.pref.value
        if res.HasField("label"):
            obj["label"] = res.label

        return obj

    def map_addr_component(component: rdap_pb2.JSCard.Address.AddressComponent) -> dict:
        if component.kind == rdap_pb2.JSCard.Address.AddressComponent.Room:
            k = "room"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Apartment:
            k = "apartment"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Floor:
            k = "floor"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Building:
            k = "building"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Number:
            k = "number"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Name:
            k = "name"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Block:
            k = "block"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.SubDistrict:
            k = "subdistrict"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.District:
            k = "district"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Locality:
            k = "locality"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Region:
            k = "region"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Postcode:
            k = "postcode"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Country:
            k = "country"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Direction:
            k = "direction"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Landmark:
            k = "landmark"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.PostOfficeBox:
            k = "postofficebox"
        elif component.kind == rdap_pb2.JSCard.Address.AddressComponent.Separator:
            k = "separator"
        else:
            k = ""

        obj = {
            "@type": "AddressComponent",
            "value": component.value,
            "kind": k,
        }
        if component.HasField("pronounce"):
            obj["pronounce"] = map_pronounce(component.pronounce)
        return obj

    def map_address(addr: rdap_pb2.JSCard.Address) -> dict:
        obj = {
            "@type": "Address",
        }

        if len(addr.components):
            obj["components"] = list(map(map_addr_component, addr.components))
        if addr.HasField("country_code"):
            obj["countryCode"] = addr.country_code.value
        if addr.HasField("coordinates"):
            obj["coordinates"] = addr.coordinates.value
        if addr.HasField("timezone"):
            obj["timeZone"] = addr.timezone.value
        if addr.HasField("full"):
            obj["full"] = addr.full.value
        if addr.HasField("pronounce"):
            obj["pronounce"] = addr.pronounce.value
        if addr.HasField("default_seperator"):
            obj["defaultSeparator"] = addr.default_seperator.value
        if addr.HasField("context"):
            obj["contexts"] = map_context(addr.context)
        if addr.HasField("preference"):
            obj["pref"] = addr.preference.value

        return obj

    card_dict = {
        "@type": "Card",
        "version": "1.0",
        "uid": card.uid,
    }
    if card.HasField("created"):
        card_dict["created"] = card.created.ToDatetime().isoformat()
    if card.HasField("updated"):
        card_dict["updated"] = card.updated.ToDatetime().isoformat()
    if card.HasField("language"):
        card_dict["language"] = card.language.value
    if card.HasField("product_id"):
        card_dict["prodId"] = card.product_id.value

    if card.kind == rdap_pb2.JSCard.Individual:
        card_dict["kind"] = "individual"
    elif card.kind == rdap_pb2.JSCard.Group:
        card_dict["kind"] = "group"
    elif card.kind == rdap_pb2.JSCard.Org:
        card_dict["kind"] = "org"
    elif card.kind == rdap_pb2.JSCard.Location:
        card_dict["kind"] = "location"
    elif card.kind == rdap_pb2.JSCard.Device:
        card_dict["kind"] = "device"
    elif card.kind == rdap_pb2.JSCard.Application:
        card_dict["kind"] = "application"

    for member in list(card.members):
        if "members" not in card_dict:
            card_dict["members"] = {}

        card_dict["members"][member] = True

    if card.HasField("name"):
        card_dict["name"] = {
            "@type": "Name",
        }

        if card.name.components:
            card_dict["name"]["components"] = [
                map_name_component(c) for c in card.name.components
            ]
        if card.name.HasField("default_separator"):
            card_dict["name"]["defaultSeparator"] = card.name.default_separator.value
        if card.name.HasField("full_name"):
            card_dict["name"]["full"] = card.name.full_name.value
        if card.name.HasField("pronounce"):
            card_dict["name"]["pronounce"] = map_pronounce(card.name.pronounce)

    for k, v in card.nick_names.items():
        if "nickNames" not in card_dict:
            card_dict["nickNames"] = {}

        card_dict["nickNames"][k] = {
            "@type": "NickName",
            "name": v.name,
        }

        if v.HasField("context"):
            card_dict["nickNames"][k]["contexts"] = map_context(v.context)
        if v.HasField("preference"):
            card_dict["nickNames"][k]["pref"] = v.preference.value

    for k, v in card.organisations.items():
        if "organizations" not in card_dict:
            card_dict["organizations"] = {}

        card_dict["organizations"][k] = {
            "@type": "Organization",
        }

        if v.HasField("name"):
            card_dict["organizations"][k]["name"] = v.name.value
        if v.units:
            card_dict["organizations"][k]["units"] = [map_org_unit(u) for u in v.units]
        if v.HasField("sort_as"):
            card_dict["organizations"][k]["sortAs"] = v.sort_as.value
        if v.HasField("context"):
            card_dict["organizations"][k]["contexts"] = map_context(v.context)

    if card.HasField("speak_to_as"):
        card_dict["speakToAs"] = {
            "@type": "SpeakToAs",
        }

        if card.speak_to_as.grammatical_gender == rdap_pb2.JSCard.SpeakToAs.Animate:
            card_dict["speakToAs"]["grammaticalGender"] = "animate"
        elif card.speak_to_as.grammatical_gender == rdap_pb2.JSCard.SpeakToAs.Common:
            card_dict["speakToAs"]["grammaticalGender"] = "common"
        elif card.speak_to_as.grammatical_gender == rdap_pb2.JSCard.SpeakToAs.Feminine:
            card_dict["speakToAs"]["grammaticalGender"] = "feminine"
        elif card.speak_to_as.grammatical_gender == rdap_pb2.JSCard.SpeakToAs.Masculine:
            card_dict["speakToAs"]["grammaticalGender"] = "masculine"
        elif card.speak_to_as.grammatical_gender == rdap_pb2.JSCard.SpeakToAs.Neuter:
            card_dict["speakToAs"]["grammaticalGender"] = "neuter"
        elif card.speak_to_as.grammatical_gender == rdap_pb2.JSCard.SpeakToAs.Inanimate:
            card_dict["speakToAs"]["grammaticalGender"] = "inanimate"

        for k, v in card.speak_to_as.pronouns.items():
            if "pronouns" not in card_dict["speakToAs"]:
                card_dict["speakToAs"]["pronouns"] = {}

            card_dict["speakToAs"]["pronouns"][k] = {
                "@type": "Pronouns",
                "pronouns": v.pronouns,
            }

            if v.HasField("context"):
                card_dict["speakToAs"]["pronouns"][k]["contexts"] = map_context(v.context)
            if v.HasField("preference"):
                card_dict["speakToAs"]["pronouns"][k]["pref"] = v.preference.value

    for k, v in card.titles.items():
        if "titles" not in card_dict:
            card_dict["titles"] = {}

        if v.kind == rdap_pb2.JSCard.Title.Title:
            t = "title"
        elif v.kind == rdap_pb2.JSCard.Title.Role:
            t = "role"

        card_dict["titles"][k] = {
            "@type": "Title",
            "name": v.name,
            "kind:": t,
        }

        if v.HasField("organisation"):
            card_dict["titles"][k]["organization"] = v.organisation.value

    for k, v in card.emails.items():
        if "emails" not in card_dict:
            card_dict["emails"] = {}

        card_dict["emails"][k] = {
            "@type": "Email",
            "address": v.email,
        }

        if v.HasField("context"):
            card_dict["emails"][k]["contexts"] = map_context(v.context)
        if v.HasField("preference"):
            card_dict["emails"][k]["pref"] = v.preference.value
        if v.HasField("label"):
            card_dict["emails"][k]["label"] = v.label.value

    for k, v in card.online_services.items():
        if "onlineServices" not in card_dict:
            card_dict["onlineServices"] = {}

        card_dict["onlineServices"][k] = {
            "@type": "OnlineService",
        }

        if v.HasField("service"):
            card_dict["onlineServices"][k]["service"] = v.service.value
        if v.HasField("uri"):
            card_dict["onlineServices"][k]["uri"] = v.uri.value
        if v.HasField("user"):
            card_dict["onlineServices"][k]["user"] = v.user.value
        if v.HasField("context"):
            card_dict["onlineServices"][k]["contexts"] = map_context(v.context)
        if v.HasField("preference"):
            card_dict["onlineServices"][k]["pref"] = v.preference.value
        if v.HasField("label"):
            card_dict["onlineServices"][k]["label"] = v.label.value

    for k, v in card.phones.items():
        if "phones" not in card_dict:
            card_dict["phones"] = {}

        features = {}

        for f in v.features:
            if f == rdap_pb2.JSCard.Phone.Mobile:
                features["mobile"] = True
            elif f == rdap_pb2.JSCard.Phone.Voice:
                features["voice"] = True
            elif f == rdap_pb2.JSCard.Phone.Text:
                features["text"] = True
            elif f == rdap_pb2.JSCard.Phone.Video:
                features["video"] = True
            elif f == rdap_pb2.JSCard.Phone.MainNumber:
                features["main-number"] = True
            elif f == rdap_pb2.JSCard.Phone.Textphone:
                features["textphone"] = True
            elif f == rdap_pb2.JSCard.Phone.Fax:
                features["fax"] = True
            elif f == rdap_pb2.JSCard.Phone.Pager:
                features["pager"] = True

        card_dict["phones"][k] = {
            "@type": "Phone",
            "number": v.number,
            "features": features,
        }

        if v.HasField("context"):
            card_dict["phones"][k]["contexts"] = map_context(v.context)
        if v.HasField("preference"):
            card_dict["phones"][k]["pref"] = v.preference.value
        if v.HasField("label"):
            card_dict["phones"][k]["label"] = v.label.value

    for k, v in card.preferred_languages.items():
        if "preferredLanguages" not in card_dict:
            card_dict["preferredLanguages"] = {}

        card_dict["preferredLanguages"][k] = list(map(map_language_pref, v.preferences))

    for k, v in card.calendars.items():
        if "calendars" not in card_dict:
            card_dict["calendars"] = {}

        if v.kind == rdap_pb2.JSCard.Calendar.Calendar:
            t = "calendar"
        elif v.kind == rdap_pb2.JSCard.Calendar.FreeBusy:
            t = "freebusy"
        else:
            continue

        card_dict["calendars"][k] = map_resource(v.resource)
        card_dict["calendars"][k]["@type"] = "Calendar"
        card_dict["calendars"][k]["kind"] = t

    for k, v in card.scheduling_addresses.items():
        if "schedulingAddresses" not in card_dict:
            card_dict["schedulingAddresses"] = {}

        card_dict["schedulingAddresses"][k] = {
            "@type": "SchedulingAddress",
            "uri": v.uri,
        }

        if v.HasField("context"):
            card_dict["schedulingAddresses"][k]["contexts"] = map_context(v.context)
        if v.HasField("preference"):
            card_dict["schedulingAddresses"][k]["pref"] = v.preference.value
        if v.HasField("label"):
            card_dict["schedulingAddresses"][k]["label"] = v.label.value

    for k, v in card.addresses.items():
        if "addresses" not in card_dict:
            card_dict["addresses"] = {}

        card_dict["addresses"][k] = map_address(v)

    for k, v in card.crypto_keys.items():
        if "cryptoKeys" not in card_dict:
            card_dict["cryptoKeys"] = {}

        card_dict["cryptoKeys"][k] = map_resource(k)
        card_dict["cryptoKeys"][k]["@type"] = "CryptoKey"

    for k, v in card.directories.items():
        if "directories" not in card_dict:
            card_dict["directories"] = {}

        if v.kind == rdap_pb2.JSCard.Directory.Directory:
            t = "directory"
        elif v.kind == rdap_pb2.JSCard.Directory.Entry:
            t = "entry"
        else:
            continue

        card_dict["directories"][k] = map_resource(k.resource)
        card_dict["directories"][k]["@type"] = "Directory"
        card_dict["directories"][k]["kind"] = t

    for k, v in card.links.items():
        if "links" not in card_dict:
            card_dict["links"] = {}

        if v.kind == rdap_pb2.JSCard.Link.Contact:
            t = "contact"
        else:
            continue

        card_dict["links"][k] = map_resource(v.resource)
        card_dict["links"][k]["@type"] = "Link"
        card_dict["links"][k]["kind"] = t

    for k, v in card.media.items():
        if "media" not in card_dict:
            card_dict["media"] = {}

        if v.kind == rdap_pb2.JSCard.Media.Photo:
            t = "photo"
        elif v.kind == rdap_pb2.JSCard.Media.Sound:
            t = "sound"
        elif v.kind == rdap_pb2.JSCard.Media.Logo:
            t = "logo"
        else:
            continue

        card_dict["media"][k] = map_resource(v.resource)
        card_dict["media"][k]["@type"] = "Media"
        card_dict["media"][k]["kind"] = t

    for k, v in card.anniversaries.items():
        if "anniversaries" not in card_dict:
            card_dict["anniversaries"] = {}

        if v.kind == rdap_pb2.JSCard.Anniversary.Birth:
            t = "birth"
        elif v.kind == rdap_pb2.JSCard.Anniversary.Death:
            t = "death"
        elif v.kind == rdap_pb2.JSCard.Anniversary.Wedding:
            t = "wedding"
        else:
            continue

        card_dict["anniversaries"][k] = {
            "@type": "Anniversary",
            "kind": t,
        }

        if v.WhichOneof("date") == "timestamp":
            card_dict["anniversaries"][k]["date"] = {
                "@type": "Timestamp",
                "utc": v.timestamp.ToDatetime().isoformat()
            }
        elif v.WhichOneof("date") == "partial_date":
            card_dict["anniversaries"][k]["date"] = {
                "@type": "PartialDate",
            }
            if v.partial_date.HasField("year"):
                card_dict["anniversaries"][k]["date"]["year"] = v.partial_date.year.value
            if v.partial_date.HasField("month"):
                card_dict["anniversaries"][k]["date"]["month"] = v.partial_date.month.value
            if v.partial_date.HasField("day"):
                card_dict["anniversaries"][k]["date"]["day"] = v.partial_date.day.value
            if v.partial_date.HasField("calendar_scale"):
                card_dict["anniversaries"][k]["date"]["calendarScale"] = v.partial_date.calendar_scale.value

        if v.HasField("place"):
            card_dict["anniversaries"][k]["place"] = map_address(v.address)

    for k in card.keywords:
        if "keywords" not in card_dict:
            card_dict["keywords"] = {}

        card_dict["keywords"][k] = True

    for k, v in card.notes.items():
        if "notes" not in card_dict:
            card_dict["notes"] = {}

        card_dict["notes"][k] = {
            "@type": "Note",
            "note": v.note,
        }

        if v.HasField("created"):
            card_dict["notes"][k]["created"] = v.created.ToDatetime().isoformat()
        if v.HasField("author"):
            card_dict["notes"][k]["author"] = {
                "@type": "Author",
            }
            if v.author.HasField("name"):
                card_dict["notes"][k]["author"]["name"] = v.author.name.value
            if v.author.HasField("uri"):
                card_dict["notes"][k]["author"]["uri"] = v.author.uri.value

    for k, v in card.personal_info.items():
        if "personalInfo" not in card_dict:
            card_dict["personalInfo"] = {}

        if v.kind == rdap_pb2.JSCard.PersonalInfo.Expertise:
            t = "expertise"
        elif v.kind == rdap_pb2.JSCard.PersonalInfo.Hobby:
            t = "hobby"
        elif v.kind == rdap_pb2.JSCard.PersonalInfo.Interest:
            t = "interest"
        else:
            continue

        if v.level == rdap_pb2.JSCard.PersonalInfo.NotSet:
            l = None
        elif v.level == rdap_pb2.JSCard.PersonalInfo.Low:
            l = "low"
        elif v.level == rdap_pb2.JSCard.PersonalInfo.Medium:
            l = "medium"
        elif v.level == rdap_pb2.JSCard.PersonalInfo.High:
            l = "high"
        else:
            continue

        card_dict["personalInfo"][k] = {
            "@type": "PersonalInfo",
            "kind": t,
            "value": v.value,
        }

        if l:
            card_dict["personalInfo"][k]["level"] = l
        if v.HasField("list_as"):
            card_dict["personalInfo"][k]["listAs"] = v.list_as.value
        if v.HasField("label"):
            card_dict["personalInfo"][k]["label"] = v.label.value

    return card_dict


def map_entity(entity: rdap_pb2.Entity) -> dict:
    out = {
        "objectClassName": "entity",
        "handle": entity.handle,
        "roles": map_roles(entity.roles),
        "publicIds": map_public_ids(entity.public_ids),
        "entities": map_entities(entity.entities),
        "events": map_events(entity.events),
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
            "v4": list(name_server.ip_addresses.v4),
            "v6": list(name_server.ip_addresses.v6)
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
        "rdap_objectTag_level_0",
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
        "links": [{
            "href": "https://icann.org/epp",
            "title": "More information on domain status codes"
        }]
    }, {
        "title": "RDDS Inaccuracy Complaint Form",
        "description": [
            "URL of the ICANN RDDS Inaccuracy Complaint Form: https://icann.org/wicf"
        ],
        "links": [{
            "href": "https://icann.org/wicf",
            "title": "ICANN RDDS Inaccuracy Complaint Form"
        }]
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
            "links": [{
                "href": "https://whois-web.as207960.net"
            }]
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
