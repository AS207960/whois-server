#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub mod whois {
    tonic::include_proto!("whois");
}
pub mod rdap {
    tonic::include_proto!("rdap");
}

lazy_static! {
    static ref NOTICE: Vec<u8> = {
        let txt_file = include_str!("notice.txt")
            .replace("\\cBB", "\x1b[38;5;81m")
            .replace("\\cBM", "\x1b[38;5;218m")
            .replace("\\cBW", "\x1b[38;5;231m")
            .replace("\\cRS", "\x1b[0m");
        txt_file.as_bytes().to_owned()
    };
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let mut listener = tokio::net::TcpListener::bind("[::]:43").await.expect("Unable to bind to socket");
    let client = rdap::rdap_client::RdapClient::connect(
        std::env::var("GRPC_SERVER").unwrap_or("http://[::1]:50051".to_string())
    ).await.expect("Unable to connect to gRPC server");

    loop {
        let (socket, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!("Error accepting connection: {}", e);
                return
            }
        };
        process_socket(socket, client.clone()).await;
    }
}

fn proto_to_chrono(time: &prost_types::Timestamp) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::offset::TimeZone;
    chrono::Utc
        .timestamp_opt(time.seconds, time.nanos as u32)
        .single()
}

fn event_to_whois(event: &rdap::Event, prefix: &str) -> Vec<String> {
    let mut out = vec![];
    match rdap::EventAction::from_i32(event.action) {
        Some(a) => {
            let event_type = match a {
                rdap::EventAction::EventRegistration => "Creation",
                rdap::EventAction::EventReregistration => "Reregistration",
                rdap::EventAction::EventLastChanged => "Updated",
                rdap::EventAction::EventExpiration => "Expiration",
                rdap::EventAction::EventDeletion => "Deletion",
                rdap::EventAction::EventReinstantiation => "Reinstantiation",
                rdap::EventAction::EventTransfer => "Last Transfer",
                rdap::EventAction::EventLocked => "Locked",
                rdap::EventAction::EventUnlocked => "Unlocked",
                rdap::EventAction::EventRegistrarExpiration => "Registrar expiration",
                rdap::EventAction::EventLastUpdateOfRdap => "Last update of WHOIS",
            };
            match &event.date {
                Some(d) => match proto_to_chrono(d) {
                    Some(d) => out.push(format!("{}{} Date: {}", prefix, event_type, d.to_rfc3339())),
                    None => {}
                },
                None => {}
            }
        },
        None => {}
    }
    out
}

fn public_ids_to_whois(public_ids: &[rdap::PublicId]) -> Vec<String> {
    let mut out = vec![];
    for public_id in public_ids {
        out.push(format!("{}: {}", public_id.r#type, public_id.identifier))
    }
    out
}

fn status_to_whois(status: i32, prefix: &str) -> Vec<String> {
    let mut out = vec![];
    match rdap::Status::from_i32(status) {
        Some(a) => {
            let event_type = match a {
                rdap::Status::Active => "active",
                rdap::Status::Validated => "validated",
                rdap::Status::RenewProhibited => "renewProhibited",
                rdap::Status::UpdateProhibited => "updateProhibited",
                rdap::Status::TransferProhibited => "transferProhibited",
                rdap::Status::DeleteProhibited => "deleteProhibited",
                rdap::Status::Proxy => "proxy",
                rdap::Status::Private => "private",
                rdap::Status::Removed => "removed",
                rdap::Status::Obscured => "obscured",
                rdap::Status::Associated => "linked",
                rdap::Status::Inactive => "inactive",
                rdap::Status::Locked => "locked",
                rdap::Status::PendingCreate => "pendingCreate",
                rdap::Status::PendingRenew => "pendingRenew",
                rdap::Status::PendingTransfer => "pendingTransfer",
                rdap::Status::PendingUpdate => "pendingUpdate",
                rdap::Status::PendingDelete => "pendingDelete",
                rdap::Status::PendingRestore => "pendingRestre",
                rdap::Status::AddPeriod => "addPeriod",
                rdap::Status::AutoRenewPeriod => "autoRenewPeriod",
                rdap::Status::RenewPeriod => "renewPeriod",
                rdap::Status::RedemptionPeriod => "redemptionPeriod",
                rdap::Status::TransferPeriod => "transferPeriod",
                rdap::Status::ClientRenewProhibited => "clientRenewProhibited",
                rdap::Status::ClientUpdateProhibited => "clientUpdateProhibited",
                rdap::Status::ClientTransferProhibited => "clientTransferProhibited",
                rdap::Status::ClientDeleteProhibited => "clientDeleteProhibited",
                rdap::Status::ClientHold => "clientHold",
                rdap::Status::ServerRenewProhibited => "serverRenewProhibited",
                rdap::Status::ServerUpdateProhibited => "serverUpdateProhibited",
                rdap::Status::ServerTransferProhibited => "serverTransferProhibited",
                rdap::Status::ServerDeleteProhibited => "serverDeleteProhibited",
                rdap::Status::ServerHold => "serverHold",
            };
            out.push(format!("{}Status: {}", prefix, event_type));
        },
        None => {}
    }
    out
}

fn remark_to_whois(remark: &rdap::Remark, prefix: &str) -> Vec<String> {
    let mut out = vec![];
    let title = match &remark.title {
        Some(t) => format!("{}: ", t),
        None => "".to_string()
    };
    for line in remark.description.split("\n") {
        out.push(format!("{}Remarks: {}{}", prefix, title, line))
    }
    out
}

fn card_to_whois(card: &rdap::JCard) -> Vec<String> {
    let mut out = vec![];
    for property in &card.properties {
        let mut name = match property.name.as_str() {
            "fn" => "Name",
            "kind" => "Kind",
            "photo" => "Photo",
            "bday" => "Birthday",
            "adr" => "Address",
            "tel" => "Telephone",
            "email" => "Email",
            "lang" => "Language",
            "title" => "Title",
            "role" => "Role",
            "logo" => "Logo",
            "url" => "URL",
            "org" => "Organisation",
            "note" => "Note",
            n => n
        }.to_string();
        for (key, value) in property.properties.iter() {
            name += &format!(", {} {}", key, value);
        }
        match &property.value {
            Some(rdap::j_card::property::Value::Text(text)) => {
                let text = match property.name.as_str() {
                    "kind" => match text.as_str() {
                        "org" => "Organisation",
                        "group" => "Group",
                        "individual" => "Individual",
                        t => t
                    }.to_string(),
                    _ => text.to_string()
                };
                out.push(format!("{}: {}", name, text))
            },
            Some(rdap::j_card::property::Value::TextArray(texts)) => {
                if property.name == "adr" {
                    if let Some(street) = texts.data.get(0) {
                        if street != "" {
                            out.push(format!("Street: {}", street))
                        }
                    }
                    if let Some(street) = texts.data.get(1) {
                        if street != "" {
                            out.push(format!("Street: {}", street))
                        }
                    }
                    if let Some(street) = texts.data.get(2) {
                        if street != "" {
                            out.push(format!("Street: {}", street))
                        }
                    }
                    if let Some(locality) = texts.data.get(3) {
                        if locality != "" {
                            out.push(format!("Locality: {}", locality))
                        }
                    }
                    if let Some(region) = texts.data.get(4) {
                        if region != "" {
                            out.push(format!("Region: {}", region))
                        }
                    }
                    if let Some(post_code) = texts.data.get(5) {
                        if post_code != "" {
                            out.push(format!("Postal Code: {}", post_code))
                        }
                    }
                    if let Some(country) = texts.data.get(6) {
                        if country != "" {
                            out.push(format!("Country: {}", country))
                        }
                    }
                    if let Some(cc) = property.properties.get("cc") {
                        out.push(format!("Country Code: {}", cc.to_ascii_uppercase()))
                    }
                } else {
                    for text in &texts.data {
                        if text != "" {
                            out.push(format!("{}: {}", name, text))
                        }
                    }
                }
            },
            Some(rdap::j_card::property::Value::Uri(uri)) => {
                out.push(format!("{}: {}", name, uri))
            },
            Some(rdap::j_card::property::Value::Date(date)) => {
                if let Some(date) = proto_to_chrono(date) {
                    out.push(format!("{}: {}", name, date.date().format("%F")))
                }
            },
            Some(rdap::j_card::property::Value::Time(date)) => {
                if let Some(date) = proto_to_chrono(date) {
                    out.push(format!("{}: {}", name, date.time().format("%T")))
                }
            },
            Some(rdap::j_card::property::Value::DateTime(date)) => {
                if let Some(date) = proto_to_chrono(date) {
                    out.push(format!("{}: {}", name, date.to_rfc3339()))
                }
            },
            Some(rdap::j_card::property::Value::Timestamp(date)) => {
                if let Some(date) = proto_to_chrono(date) {
                    out.push(format!("{}: {}", name, date.to_rfc3339()))
                }
            },
            Some(rdap::j_card::property::Value::Boolean(value)) => {
                out.push(format!("{}: {}", name, match value {
                    true => "yes",
                    false => "no"
                }))
            },
            Some(rdap::j_card::property::Value::Integer(value)) => {
                out.push(format!("{}: {}", name, value))
            },
            Some(rdap::j_card::property::Value::Float(value)) => {
                out.push(format!("{}: {}", name, value))
            },
            Some(rdap::j_card::property::Value::Language(value)) => {
                out.push(format!("{}: {}", name, value.to_ascii_uppercase()))
            },
            _ => {}
        }
    }
    out
}

fn entity_to_whois(entity: &rdap::Entity, prefix: &str) -> Vec<String> {
    let mut out = vec![];
    let mut lines = vec![];
    let mut roles = vec![];
    for role in &entity.roles {
        match rdap::EntityRole::from_i32(*role) {
            Some(r) => roles.push(match r {
                rdap::EntityRole::RoleRegistrant => "Registrant",
                rdap::EntityRole::RoleTechnical => "Tech",
                rdap::EntityRole::RoleAdministrative => "Admin",
                rdap::EntityRole::RoleBilling => "Billing",
                rdap::EntityRole::RoleAbuse => "Abuse",
                rdap::EntityRole::RoleRegistrar => "Registrar",
                rdap::EntityRole::RoleReseller => "Reseller",
                rdap::EntityRole::RoleSponsor => "Sponsor",
                rdap::EntityRole::RoleProxy => "Proxy",
                rdap::EntityRole::RoleNotifications => "Notifications",
                rdap::EntityRole::RoleNoc => "NOC",
            }),
            None => {}
        }
    }
    lines.push(format!("Handle: {}", entity.handle));
     for event in &entity.events {
        lines.extend(event_to_whois(event, ""));
    }
    for status in &entity.statuses {
        lines.extend(status_to_whois(*status, ""));
    }
    lines.extend(public_ids_to_whois(&entity.public_ids));
    if let Some(card) = &entity.card {
        lines.extend(card_to_whois(card));
    }
    for remark in &entity.remarks {
        lines.extend(remark_to_whois(remark, ""));
    }
    for entity in &entity.entities {
        lines.extend(entity_to_whois(entity, ""));
    }
    for role in roles {
        for line in &lines {
            out.push(format!("{}{} {}", prefix, role, line))
        }
    }
    out
}


fn name_server_to_whois(name_server: &rdap::NameServer) -> Vec<String> {
    let mut out = vec![];
    out.push(format!("Name Server: {}", name_server.name));
    out.push(format!("Name Server Handle: {}", name_server.handle));
    if let Some(ip_addresses) = &name_server.ip_addresses {
        for v4 in &ip_addresses.v4 {
            out.push(format!("Name Server IPv4 Address: {}", v4))
        }
        for v6 in &ip_addresses.v6 {
            out.push(format!("Name Server IPv6 Address: {}", v6))
        }
    }
    for event in &name_server.events {
        out.extend(event_to_whois(event, "Name Server "));
    }
    for status in &name_server.statuses {
        out.extend(status_to_whois(*status, "Name Server "));
    }
    for entity in &name_server.entities {
        out.extend(entity_to_whois(entity, "Name Server "));
    }
    for remark in &name_server.remarks {
        out.extend(remark_to_whois(remark, "Name Server "));
    }
    out
}

fn domain_to_whois(domain: &rdap::Domain) -> Vec<String> {
    let mut out = vec![];
    out.push(format!("Domain Name: {}", domain.name));
    out.push(format!("Registry Domain ID: {}", domain.handle));
    for event in &domain.events {
        out.extend(event_to_whois(event, ""));
    }
    for status in &domain.statuses {
        out.extend(status_to_whois(*status, "Domain "));
    }
    out.extend(public_ids_to_whois(&domain.public_ids));
    for entity in &domain.entities {
        out.extend(entity_to_whois(entity, ""));
    }
    for remark in &domain.remarks {
        out.extend(remark_to_whois(remark, "Domain "));
    }
    for name_server in &domain.name_servers {
        out.extend(name_server_to_whois(name_server));
    }
    if let Some(sec_dns) = &domain.sec_dns {
        if let Some(delegation_signed) = sec_dns.delegation_signed {
            if delegation_signed {
                out.push("DNSSEC: signedDelegation".to_string())
            } else {
                out.push("DNSSEC: unsigned".to_string())
            }
            for ds_data in &sec_dns.ds_data {
                out.push(format!("DNSSEC DS Data: {} {} {} {}", ds_data.key_tag, ds_data.algorithm, ds_data.digest_type, ds_data.digest))
            }
            for key_data in &sec_dns.key_data {
                out.push(format!("DNSSEC Key Data: {} {} {} {}", key_data.flags, key_data.protocol, key_data.algorithm, key_data.public_key))
            }
        }
    }
    out.push("URL of the ICANN RDDS Inaccuracy Complaint Form: https://icann.org/wicf".to_string());
    out
}

async fn process_socket<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin>(mut socket: T, mut client: rdap::rdap_client::RdapClient<tonic::transport::Channel>) {
    let mut buf: Vec<u8> = vec![];
    loop {
        let byte = match socket.read_u8().await {
            Ok(b) => b,
            Err(_) => {
                return;
            }
        };
        if char::from(byte) != '\r' {
            buf.push(byte);
        } else {
            break;
        }
    }
    let byte = match socket.read_u8().await {
        Ok(b) => b,
        Err(_) => {
            return;
        }
    };
    if char::from(byte) != '\n' {
        return;
    }
    let query_str = match String::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => {
            return;
        }
    };

    let query_str_ascii = match idna::domain_to_ascii(&query_str) {
        Ok(r) => r,
        Err(_) => query_str
    };

    let request = tonic::Request::new(rdap::DomainSearchRequest {
        query: Some(rdap::domain_search_request::Query::Name(query_str_ascii))
    });

     match client.domain_search(request).await {
        Ok(r) => {
            let response = r.into_inner();
            match response.response {
                Some(rdap::domain_search_response::Response::Success(success)) => {
                    if success.data.is_empty() {
                        match socket.write(b">>> No results\r\n\r\n").await {
                            Ok(_) => {}
                            Err(_) => {
                                return;
                            }
                        };
                    } else {
                        for domain in &success.data {
                            let out = domain_to_whois(domain);
                            for l in &out {
                                match socket.write(format!("{}\r\n", l).as_bytes()).await {
                                    Ok(_) => {}
                                    Err(_) => {
                                        return;
                                    }
                                };
                            }
                            match socket.write(b"\r\n").await {
                                Ok(_) => {}
                                Err(_) => {
                                    return;
                                }
                            };
                        }
                    }
                },
                Some(rdap::domain_search_response::Response::Redirect(_)) => {
                    match socket.write(b">>> Error: Object not found here\r\n\r\n").await {
                        Ok(_) => {}
                        Err(_) => {
                            return;
                        }
                    };
                }
                Some(rdap::domain_search_response::Response::Error(error)) => {
                    match socket.write(format!(">>> Error: {}\r\n\r\n", error.description).as_bytes()).await {
                        Ok(_) => {}
                        Err(_) => {
                            return;
                        }
                    };
                }
                None => {}
            }
//            for object in response.objects {
//                for element in object.elements {
//                    match socket.write(format!("{}: {}\r\n", element.key, element.value).as_bytes()).await {
//                        Ok(_) => {}
//                        Err(_) => {
//                            return;
//                        }
//                    };
//                }
//                match socket.write(b"\r\n").await {
//                    Ok(_) => {}
//                    Err(_) => {
//                        return;
//                    }
//                };
//            }
        },
        Err(e) => {
            match socket.write(format!(">>> Error: {:?}, {}\r\n\r\n", e.code(), e.message()).as_bytes()).await {
                Ok(_) => {}
                Err(_) => {
                    return;
                }
            };
        }
    };

    match socket.write(&NOTICE).await {
        Ok(_) => {}
        Err(_) => {}
    };
}