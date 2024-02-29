use std::{env, convert::Infallible} ;
use std::net::SocketAddr;
use std::sync::Arc;
use std::string::String;
use std::sync::atomic::{AtomicUsize, Ordering};

use core::fmt::Write;

use futures::lock::Mutex;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::StatusCode;
use base64::{engine::general_purpose, Engine as _};
//use hyper::header::{Headers, Authorization};
use std::str::FromStr;
use std::fs;
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use simple_hyper_server_tls::*;
use openssl::rsa::Rsa;
use pem::{Pem, encode_config, EncodeConfig, LineEnding};
use ipnet::Ipv4Net;
use xml2json_rs::XmlBuilder;

use openssl::x509::X509Builder;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use std::ops::Deref;

use std::net::Ipv4Addr;
use rand::{thread_rng, Rng};

use std::iter::zip;

type HmacSha256 = Hmac<Sha256>;

fn jsonobj_to_strret(mut json: json::JsonValue, req_id: usize) -> String {
    json["ResponseContext"] = json::JsonValue::new_object();
    //0475ca1e-d0c5-441d-712a-da55a4175157
    json["ResponseContext"]["RequestId"] = format!("0475ca1e-0001-0002-0003-{:08x}", req_id).into();
    json::stringify_pretty(json, 3)
}

fn have_request_filter(filter: & json::JsonValue, vm: & json::JsonValue,
                       lookfor: & str, src: & str, old: bool) -> bool {
    if !old {
        return false;
    }
    fn comp_filter(elem: &json::JsonValue, needle: & json::JsonValue) -> bool {
        if elem == needle {
            return true;
        }
        if elem.is_string() && needle.is_string() {
            let mut s_elem = elem.as_str().unwrap();
            let mut s_needle = needle.as_str().unwrap();

            let mut neddle_chars = s_needle.chars();
            let mut elem_chars = s_elem.chars();

            loop {
                let elem_c = elem_chars.next();
                let needle_c = neddle_chars.next();

                if elem_c.is_none() || needle_c.is_none() {
                    return (elem_c.is_none() && needle_c.is_none()) || s_needle == "*"
                }
                if needle_c == elem_c {
                    continue;
                }
                // Game on
                if needle_c == Some('*') {
                    // if * at the end, then everything goes, return true
                    if s_needle == "*" {
                        return true;
                    }
                    s_needle = neddle_chars.as_str();
                    // if there is something after *, headache incoming
                    if let Some(star_pos) = s_needle.find('*') {
                        let (to_search, then) = s_needle.split_at(star_pos);
                        if let Some((_, then_el)) = s_elem.split_once(to_search) {
                            s_elem = then_el;
                            s_needle = then;
                            elem_chars = then_el.chars();
                            neddle_chars = s_needle.chars();
                        } else {
                            return false;
                        }
                        continue;
                    } else {
                        // if s_needle is at at elem_chars end, return true, otherwise return false
                        let test = s_elem.strip_suffix(s_needle);
                        return test.is_some();
                    }
                }
                return false;
            }
        }
        false
    }

    if filter.has_key(lookfor) {

        for l in filter[lookfor].members() {
            if vm.has_key(src) && comp_filter(&vm[src], l) {
                return true;
            }
        }
        false
    } else {
        true
    }
}

fn serv_error(req_id: usize , mut json: json::JsonValue,
                error:  &str) ->
    Result<(String, StatusCode), (String, StatusCode)> {
        eprintln!("serv_Error: {}", error);
        json["Errors"] = json::array![json::object!{Details: error}];
        Err((jsonobj_to_strret(json, req_id), StatusCode::from_u16(503).unwrap()))
}

fn bad_argument(req_id: usize ,mut json: json::JsonValue,
                error:  &str) ->
    Result<(String, StatusCode), (String, StatusCode)> {
        eprintln!("bad_argument: {}", error);
        json["Errors"] = json::array![json::object!{Details: error}];
        Err((jsonobj_to_strret(json, req_id), StatusCode::from_u16(400).unwrap()))
}

fn eval_bad_auth(req_id: usize ,mut json: json::JsonValue,
                 error:  &str) -> Result<(String, StatusCode), (String, StatusCode)> {
    json["Errors"] = json::array![json::object!{Details: error}];
    Err((jsonobj_to_strret(json, req_id), StatusCode::UNAUTHORIZED))
}

fn bad_auth(error: String) -> Result<Response<Body>,Infallible> {
    let mut response = Response::new(Body::empty());

    eprintln!("bad_auth: {}", error);
    response.headers_mut().append("WWW-Authenticate", "Basic".parse().unwrap());
    *response.body_mut() = Body::from(error);
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    Ok(response)
}

fn remove_duplicate_slashes(path: &str) -> String {
    let mut new_path = String::new();
    let mut last_char = '_';
    for c in path.chars() {
        if c == '/' {
            if last_char != '/' {
                new_path.push(c);
            }
        } else {
            new_path.push(c);
        }
        last_char = c;
    }
    new_path
}

fn try_conver_response(rres: Result<(String, StatusCode), (String, StatusCode)>,
                       need_convert: bool) -> (String, hyper::StatusCode) {
    let res = match rres {
        Ok(r) => r,
        Err(r) => r
    };
    if !need_convert {
        return res
    }

    let mut xml_builder = XmlBuilder::default();
    let xml = xml_builder.build_from_json_string(res.0.as_str());

    (xml.unwrap(), StatusCode::OK)
}

#[derive(PartialEq)]
enum AuthType {
    None,
    Basic,
    AkSk
}

#[derive(Debug)]
enum RicCall {
    Root,
    Debug,

    CreateNet,
    CreateKeypair,
    CreateVms,
    CreateTags,
    CreateFlexibleGpu,
    CreateImage,
    CreateVolume,
    CreateLoadBalancer,
    CreateSecurityGroup,
    CreateSecurityGroupRule,
    CreateDirectLink,
    CreateInternetService,
    CreatePublicIp,
    CreateSubnet,
    CreateRouteTable,
    CreateRoute,

    DeleteNet,
    DeleteSubnet,
    DeleteKeypair,
    DeleteLoadBalancer,
    DeleteVms,
    DeleteTags,
    DeleteSecurityGroup,
    DeleteSecurityGroupRule,
    DeleteFlexibleGpu,
    DeleteDirectLink,
    DeleteInternetService,
    DeletePublicIp,
    DeleteRouteTable,
    DeleteRoute,
    DeleteVolume,

    ReadAccessKeys,
    ReadAccounts,
    ReadFlexibleGpus,
    ReadConsumptionAccount,
    ReadImages,
    ReadDirectLinks,
    ReadKeypairs,
    ReadNets,
    ReadLoadBalancers,
    ReadVms,
    ReadVolumes,
    ReadQuotas,
    ReadSecurityGroups,
    ReadApiAccessPolicy,
    ReadInternetServices,
    ReadLinkPublicIps,
    ReadPublicIps,
    ReadRouteTables,
    ReadSubnets,
    ReadAdminPassword,
    ReadTags,

    LinkInternetService,
    LinkRouteTable,
    LinkVolume,
    LinkPublicIp,
    LinkFlexibleGpu,

    UnlinkFlexibleGpu,
    UnlinkInternetService,
    UnlinkRouteTable,
    UnlinkVolume,
    UnlinkPublicIp,

    UpdateVm,

    StartVms,
    StopVms,

    // Free Calls
    ReadPublicCatalog,
    ReadRegions,
    ReadSubregions,
    ReadPublicIpRanges
}

impl RicCall {
    fn is_free(&self) -> bool {
        matches!(*self, RicCall::ReadPublicCatalog | RicCall::ReadRegions | RicCall::ReadPublicIpRanges)
    }

    #[allow(clippy::too_many_arguments)]
    fn eval(&self,
            mut main_json: futures::lock::MutexGuard<'_, json::JsonValue, >,
            cfg: futures::lock::MutexGuard<'_, json::JsonValue, >,
            bytes: hyper::body::Bytes,
            user_id: usize,
            req_id: usize,
            headers: hyper::HeaderMap<hyper::header::HeaderValue>,
            auth : AuthType)
            -> Result<(String, hyper::StatusCode), (String, hyper::StatusCode)> {

        let mut json = json::JsonValue::new_object();

        fn is_same_rule(a: &json::JsonValue, b: &json::JsonValue) -> bool {
            a["FromPortRange"] == b["FromPortRange"] &&
                a["IpProtocol"] == b["IpProtocol"] &&
                a["ToPortRange"] == b["ToPortRange"] &&
                a["IpRanges"].members().eq(b["IpRanges"].members())
        }

        macro_rules! array_remove_2 {
            ($json:expr, $req_id:expr, $array:expr, $predicate:expr) => {{
                match $array.members().position($predicate) {
                    Some(idx) => $array.array_remove(idx),
                    None => return bad_argument($req_id, $json, "Element not found(alerady destroy ?)")
                }
            }}
        }

        macro_rules! array_remove {
            ($array:expr, $predicate:expr) => {
                array_remove_2!(json, req_id, $array, $predicate)
            }
        }

        macro_rules! get_by_id {
            ($resource_type:expr, $id_name:expr, $id:expr) => {{
                match main_json[user_id][$resource_type].members().position(|m| m[$id_name] == $id) {
                    Some(idx) => Ok(($resource_type, idx)),
                    None => Err(bad_argument(req_id, json.clone(), "Element id not found"))
                }
            }}
        }

        macro_rules! flow_to_str {
            ($flow:expr) =>
            {{
                match $flow {
                    true => "InboundRules",
                    _ => "OutboundRules"
                }
            }}
        }

        macro_rules! optional_arg {
            ($in_json:expr, $arg:expr, $default:expr) => {{
                match $in_json.has_key($arg) {
                    true => $in_json[$arg].clone(),
                    _ => $default.into()
                }
            }}
        }

        macro_rules! require_arg_2 {
            ($json:expr, $req_id:expr, $in_json:expr, $arg:expr) => {{
                match $in_json.has_key($arg) {
                    true => $in_json[$arg].clone(),
                    _ => return bad_argument($req_id, $json, format!("{} required", $arg).as_str())
                }
            }}
        }

        macro_rules! require_arg {
            ($in_json:expr, $arg:expr) => {
                require_arg_2!(json, req_id, $in_json, $arg)
            }
        }

        macro_rules! require_in_json {
            ($bytes:expr) => {{
                if bytes.is_empty() {
                    return bad_argument(req_id, json, "Argument require");
                }
                match json::parse(std::str::from_utf8(&bytes).unwrap()) {
                    Ok(in_json) => in_json,
                    Err(_) => {
                        return bad_argument(req_id, json, "Invalide json");
                    }
                }
            }}
        }

        macro_rules! check_conflict {
            ($resource:expr, $to_check:expr, $json:expr) => {{
                for k in main_json[user_id][concat!(stringify!($resource), "s")].members() {
                    println!("cmp ({}): {} with {}", concat!(stringify!($resource), "Name"),
                             k[concat!(stringify!($resource), "Name")].to_string(),
                             $to_check);
                    if k[concat!(stringify!($resource), "Name")] == $to_check {
                        return bad_argument(req_id, $json, concat!(stringify!($resource),
                                                                  " Name conflict"));
                    }
                }
            }};
        }

        let users = &cfg["users"];
        //let mut ret = ("could not happen", StatusCode::NOT_IMPLEMENTED);

        println!("RicCall eval: {:?}", *self);
        if auth == AuthType::None && !self.is_free() {
            eprintln!("{:?} require auth", *self);
            return bad_argument(req_id, json, format!("{:?} require auth", *self).as_str())
        }

        match *self {
            RicCall::Root => {
                Ok(("Try POSTing to /ReadVms".to_string(), StatusCode::OK))
            },
            RicCall::Debug => {
                let hdr = format!("{:?}", headers);
                Ok((format!("data: {}\nheaders: {}\n",
                               String::from_utf8(bytes.to_vec()).unwrap(),
                               hdr), StatusCode::OK))
            },
            RicCall::ReadVms  => {

                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadVms require v4 signature")
                }

                let user_vms = &mut main_json[user_id]["Vms"];

                for vm in user_vms.members_mut() {
                    if vm["State"] == "pending" {
                        vm["State"] = "running".into()
                    } else if vm["State"] == "stopping" {
                        vm["State"] = "stopped".into()
                    }
                }

                json["Vms"] = (*user_vms).clone();

                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Ok(in_json) => {
                            println!("{:#}", in_json.dump());
                            if in_json.has_key("Filters") {
                                let filter = &in_json["Filters"];

                                json["Vms"] = json::JsonValue::new_array();

                                for vm in user_vms.members() {
                                    let mut need_add = true;

                                    need_add = have_request_filter(filter, vm,
                                                                   "VmIds", "VmId", need_add);
                                    need_add = have_request_filter(filter, vm,
                                                                   "TagValues", "VmType", need_add);
                                    need_add = have_request_filter(filter, vm,
                                                                   "TagKeys", "VmId", need_add);
                                    if need_add {
                                        json["Vms"].push((*vm).clone()).unwrap();
                                    }
                                }
                            }
                        },
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalide json");
                        }
                    }
                }
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::StopVms => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "StopVms require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let ids = require_arg!(in_json, "VmIds");
                let user_vms = &mut main_json[user_id]["Vms"];
                let mut vms_ret = json::JsonValue::new_array();

                for (_, vm) in user_vms.members_mut().enumerate() {
                    for id in ids.members() {
                        if *id == vm["VmId"] {
                            let mut new_state = "stopping";
                            if vm["State"] == "stopped" {
                                new_state = "stopped"
                            }
                            vms_ret.push(json::object!{
                                "VmId": id.to_string(),
                                "PreviousState": vm["State"].clone(),
                                "CurrentState": new_state
                            }).unwrap();
                            vm["State"] = new_state.into();
                        }
                    }
                }

                json["Vms"] = vms_ret;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::StartVms => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "StartVms require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let ids = require_arg!(in_json, "VmIds");
                let user_vms = &mut main_json[user_id]["Vms"];
                let mut vms_ret = json::JsonValue::new_array();

                for (_, vm) in user_vms.members_mut().enumerate() {
                    for id in ids.members() {
                        if *id == vm["VmId"] {
                            let mut new_state = "pending";
                            if vm["State"] == "running" {
                                new_state = "running"
                            }
                            vms_ret.push(json::object!{
                                "VmId": id.to_string(),
                                "PreviousState": vm["State"].clone(),
                                "CurrentState": new_state
                            }).unwrap();
                            vm["State"] = new_state.into();
                        }
                    }
                }

                json["Vms"] = vms_ret;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteVms  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteVms require v4 signature")
                }
                let user_vms = &mut main_json[user_id]["Vms"];

                json["Vms"] = (*user_vms).clone();

                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Ok(in_json) => {
                            // need refacto using user_vms.members().filter(FIND and do json["Vms"].push((*vm)).for_each(REMOVE)
                            println!("{:#}", in_json.dump());
                            if in_json.has_key("VmIds") {
                                let ids = &in_json["VmIds"];

                                json["Vms"] = json::JsonValue::new_array();
                                let mut rm_array = vec![];
                                for (idx, vm) in user_vms.members_mut().enumerate() {
                                    let mut need_rm = true;

                                    for id in ids.members() {
                                        if *id == vm["VmId"] {
                                            need_rm = true;
                                        }
                                    }
                                    if need_rm {
                                        vm["State"] = "terminated".into();
                                        json["Vms"].push((*vm).clone()).unwrap();
                                        rm_array.push(idx);
                                    }
                                }
                                for i in rm_array {
                                    user_vms.array_remove(i);
                                }
                            }
                        },
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalide json");
                        }
                    }
                }
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteLoadBalancer  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteLoadBalancer require v4 signature")
                }
                let user_lbu = &mut main_json[user_id]["LoadBalancers"];

                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Ok(in_json) => {
                            if in_json.has_key("LoadBalancerName") {
                                let id = &in_json["LoadBalancerName"];

                                array_remove!(user_lbu, |lbu| *id == lbu["LoadBalancerName"]);
                            }
                        },
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalide json");
                        }
                    }
                } else {
                    return bad_argument(req_id, json, "Invalide json");
                }
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteKeypair  => {
                let user_kps = &mut main_json[user_id]["Keypairs"];

                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Ok(in_json) => {
                            if in_json.has_key("KeypairName") {
                                let name = &in_json["KeypairName"];

                                let mut idx = 0;
                                let mut rm = false;
                                // can be refacto using array_remove!
                                for vm in user_kps.members() {
                                    if *name == vm["KeypairName"] {
                                        rm = true;
                                        break;
                                    }
                                    idx += 1;
                                }
                                if rm {
                                    user_kps.array_remove(idx);
                                }
                            } else {
                                return bad_argument(req_id, json, "KeypairName Missing")
                            }
                        },
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalide json");
                        }
                    }
                }
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateLoadBalancer => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateLoadBalancer require v4 signature")
                }
                let mut lb = json::object!{
                    ApplicationStickyCookiePolicies: json::array![],
                    BackendVmIds: json::array![],
                    LoadBalancerType:"internet-facing",
                    DnsName: "unimplemented",
                    HealthCheck: json::object!{
                        UnhealthyThreshold:2,
                        Timeout:5,
                        CheckInterval:30,
                        Protocol:"TCP",
                        HealthyThreshold:10,
                        Port:80
                    },
                    AccessLog: json::object!{
                        PublicationInterval:60,
                        IsEnabled:false
                    },
                    LoadBalancerStickyCookiePolicies: json::array![]
                };
                match json::parse(std::str::from_utf8(&bytes).unwrap()) {
                    Ok(in_json) => {
                        if in_json.has_key("SubregionNames") {
                            lb["SubregionNames"] = in_json["SubregionNames"].clone();
                        } else {
                            lb["SubregionNames"] = json::array!["mud-half-3a"];
                        }

                        if in_json.has_key("Tags") {
                            lb["Tags"] = in_json["Tags"].clone();
                        } else {
                            lb["Tags"] = json::array![];
                        }

                        if in_json.has_key("Subnets") {
                            lb["Subnets"] = in_json["Subnets"].clone();
                        } else {
                            lb["Subnets"] = json::array![];
                        }

                        if in_json.has_key("LoadBalancerName") {
                            let name = in_json["LoadBalancerName"].to_string();
                            check_conflict!(LoadBalancer, name, json);
                            lb["LoadBalancerName"] = json::JsonValue::String(name);
                        } else {
                            return bad_argument(req_id, json, "LoadBalancerName missing")
                        }

                        if in_json.has_key("Listeners") {
                            let mut listeners = in_json["Listeners"].clone();
                            for l in listeners.members_mut() {
                                if !l.has_key("LoadBalancerProtocol") {
                                    return bad_argument(req_id, json, "Listener require LoadBalancerProtocol");
                                }

                                if !l.has_key("BackendProtocol") {
                                    l["BackendProtocol"] = l["LoadBalancerProtocol"].clone();
                                }
                            }

                            lb["Listeners"] = listeners;
                        } else {
                            return bad_argument(req_id, json, "Listeners missing")
                        }
                    },
                    Err(_) => {
                        return bad_argument(req_id, json, "Invalid JSON format, or no input")
                    }
                }
                lb["SourceSecurityGroup"] = json::object!{
                    SecurityGroupAccountId: "unknow",
                    SecurityGroupName: "unknow"
                };
                lb["SecuredCookies"] = json::JsonValue::Boolean(false);

                main_json[user_id]["LoadBalancers"].push(
                    lb.clone()).unwrap();
                json["LoadBalancer"] = lb;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateImage => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateImage require v4 signature")
                }
                let image_id = format!("ami-{:08x}", req_id);
                let mut image = json::object!{
                    AccountId: format!("{:08x}", user_id),
                    ImageId: image_id
                };
                if !users[user_id]["login"].is_null() {
                    image["AccountAlias"] = users[user_id]["login"].clone()
                }

                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Ok(in_json) => {
                            if in_json.has_key("ImageName") {
                                image["ImageName"] = in_json["ImageName"].clone();
                            }
                        },
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalide json");
                        }
                    }
                }
                main_json[user_id]["Images"].push(
                    image.clone()).unwrap();
                json["Images"] = json::array!{image};
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateSubnet => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateSubnet require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let ip_range = require_arg!(in_json, "IpRange");
                let net_id = require_arg!(in_json, "NetId");
                let mut subnet = json::object!{
                    SubnetId: format!("subnet-{:08x}", req_id),
                    State: "available",
                    AvailableIpsCount: 16379,
                    Tags: json::array!{},
                    MapPublicIpOnLaunch: false
                };
                if in_json.has_key("SubregionName") {
                    subnet["SubregionName"] = in_json["SubregionName"].clone();
                }

                let user_nets = &mut main_json[user_id]["Nets"];
                match user_nets.members_mut().find(|net| net_id == net["NetId"]) {
                    Some(_) => {
                        // I should check the range is valide here.
                        subnet["IpRange"] = ip_range;
                        subnet["NetId"] = net_id;
                    },
                    _ => return bad_argument(req_id, json, "NetId doesn't corespond to an existing Net")
                };
                main_json[user_id]["Subnets"].push(
                    subnet.clone()).unwrap();
                json["Subnet"] = subnet;

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteRouteTable => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteRouteTable require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let user_nets = &mut main_json[user_id]["RouteTables"];
                // TODO: check subnet is destroyable
                let id = require_arg!(in_json, "RouteTableId");
                array_remove!(user_nets, |n| n["RouteTableId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteSubnet => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteSubnet require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let user_nets = &mut main_json[user_id]["Subnets"];
                // TODO: check subnet is destroyable
                let id = require_arg!(in_json, "SubnetId");
                array_remove!(user_nets, |n| n["SubnetId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateNet => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateNet require v4 signature")
                }
                let net_id = format!("vpc-{:08x}", req_id);
                let in_json = require_in_json!(bytes);
                let mut net = json::object!{
                    NetId: net_id,
                    State: "available",
                    DhcpOptionsSetId: "unimplemented",
                    Tags: json::array!{},
                    Tenancy: optional_arg!(in_json, "Tenancy", "default")
                };

                if in_json.has_key("IpRange") {
                    let iprange = in_json["IpRange"].as_str().unwrap();

                    let net_st: Result<Ipv4Net, _> = iprange.parse();

                    match net_st {
                        Ok(range) => {
                            if range.prefix_len() != 16 && range.prefix_len() != 28 {
                                return bad_argument(req_id, json, "iprange size is nope")
                            }
                            net["IpRange"] = iprange.into()
                        },
                        _ => return bad_argument(req_id, json,
                                                 "you range is pure &@*$ i meam invalide")
                    }
                } else {
                    return bad_argument(req_id, json, "l'IpRange wesh !");
                }
                main_json[user_id]["Nets"].push(
                    net.clone()).unwrap();
                json["Net"] = net;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteRoute => {
                // TODO
                json["ricochet-info"] = "CALL LOGIC NOT YET IMPLEMENTED".into();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateRoute => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateRoute require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let rt_id = require_arg!(in_json, "RouteTableId");
                let new_route = json::object!{
                    DestinationIpRange: require_arg!(in_json, "DestinationIpRange"),
                    CreationMethod: "CreateRoute",
                    State: "active"
                };
                match get_by_id!("RouteTables", "RouteTableId", rt_id) {
                    Ok((_, rt_idx)) => {
                        let rt = &mut main_json[user_id]["RouteTables"][rt_idx];
                        rt["Routes"].push(new_route).unwrap();
                        json["RouteTable"] = rt.clone();
                    },
                    _ => return bad_argument(req_id, json, "Net not found")
                }

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateRouteTable => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateRouteTable require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let net_id = require_arg!(in_json, "NetId");
                let mut rt = json::object!{
                    Tags: json::array!{},
                    RoutePropagatingVirtualGateways: json::array!{},
                    LinkRouteTables: json::array!{},
                    Routes: json::array!{
                        json::object!{
                            DestinationIpRange: "10.0.0.0/16",
                            CreationMethod: "CreateRouteTable",
                            State: "active"
                        },
                    },
                    RouteTableId: format!("rtb-{:08x}", req_id)
                };

                match get_by_id!("Nets", "NetId", net_id) {
                    Ok(_) => {rt["NetId"] = net_id},
                    _ => return bad_argument(req_id, json, "Net not found")
                }
                main_json[user_id]["RouteTables"].push(
                    rt.clone()).unwrap();
                json["RouteTable"] = rt;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::LinkFlexibleGpu => {
                let in_json = require_in_json!(bytes);
                let fgpu_id = require_arg!(in_json, "FlexibleGpuId");
                let vm_id = require_arg!(in_json, "VmId");

                let fgpu_idx = match get_by_id!("FlexibleGpus", "FlexibleGpuId", fgpu_id) {
                    Ok((_, idx)) => idx,
                    _ => return bad_argument(req_id, json, "FlexibleGpu not found")
                };
                match get_by_id!("Vms", "VmId", vm_id) {
                    Ok((_, _)) => {
                        main_json[user_id]["FlexibleGpus"][fgpu_idx]["VmId"] = vm_id;
                        main_json[user_id]["FlexibleGpus"][fgpu_idx]["State"] = "attaching".into()
                    },
                    _ => return bad_argument(req_id, json, "Vm not found")
                }

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::UnlinkFlexibleGpu => {
                let in_json = require_in_json!(bytes);
                let fgpu_id = require_arg!(in_json, "FlexibleGpuId");

                match get_by_id!("FlexibleGpus", "FlexibleGpuId", fgpu_id) {
                    Ok((_, idx)) => {
                        main_json[user_id]["FlexibleGpus"][idx].remove("VmId");
                        main_json[user_id]["FlexibleGpus"][idx]["State"] = "detaching".into()
                    },
                    _ => return bad_argument(req_id, json, "FlexibleGpu not found")
                };

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::LinkRouteTable => {
                /* Still todo */
                json["ricochet-info"] = "CALL LOGIC NOT YET IMPLEMENTED".into();
                let in_json = require_in_json!(bytes);
                json["LinkRouteTableId"] = require_arg!(in_json, "RouteTableId");
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::UnlinkRouteTable => {
                /* Still todo */
                json["ricochet-info"] = "CALL LOGIC NOT YET IMPLEMENTED".into();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::LinkInternetService => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "LinkInternetService require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let id = require_arg!(in_json, "InternetServiceId");
                let net_id = require_arg!(in_json, "NetId");

                let net_idx = get_by_id!("Nets", "NetId", net_id);
                let user_iwgs = &mut main_json[user_id]["InternetServices"];
                let iwg = match user_iwgs.members_mut().find(|iwg| id == iwg["InternetServiceId"]) {
                    Some(iwg) => iwg,
                    _ => return bad_argument(req_id, json, "SecurityGroupId doesn't corespond to an existing id")
                };

                match net_idx {
                    Ok(_) => {iwg["NetId"] = net_id},
                    _ => return bad_argument(req_id, json, "Net not found")
                };
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::LinkPublicIp => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "LinkPublicIp require v4 signature")
                }
                let in_json = require_in_json!(bytes);

                println!("{:#}", in_json.dump());

                let ip = format!("eipassoc-{:08x}", req_id);
                let ip_id = require_arg!(in_json, "PublicIpId");
                let user = &mut main_json[user_id];
                let ip_idx = match user["PublicIps"].members().position(|iwg| ip_id == iwg["PublicIpId"]) {
                    Some(idx) => idx,
                    _ => return bad_argument(req_id, json, "SecurityGroupId doesn't corespond to an existing id")
                };
                let mut to_push = json::object!{
                    LinkPublicIpId: ip.clone(),
                    PublicIpId: ip_id.clone()
                };

                if in_json.has_key("VmId") {
                    let vm_id = in_json["VmId"].clone();
                    let vm_idx =  match user["Vms"].members().position(|m| m["VmId"] == vm_id) {
                        Some(idx) => idx,
                        None => return bad_argument(req_id, json.clone(), "Element id not found")
                    };
                    to_push["VmId"] = vm_id.clone();
                    user["PublicIps"][ip_idx]["VmId"] = vm_id;
                    user["PublicIps"][ip_idx]["LinkPublicIpId"] = ip.clone().into();
                    user["Vms"][vm_idx]["PublicIp"] = user["PublicIps"][ip_idx]["PublicIp"].clone();
                }

                /*
                 * link to nic still TODO
                 */
                user["LinkPublicIps"].push(to_push).unwrap();
                json["LinkPublicIpId"] = ip.clone().into();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::UnlinkPublicIp => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "UnlinkPublicIp require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());
                if in_json.has_key("PublicIpId") {
                    let id = require_arg!(in_json, "PublicIpId");

                    let user_iwgs = &mut main_json[user_id]["PublicIps"];
                    match user_iwgs.members_mut().find(|iwg| id == iwg["PublicIpId"]) {
                        Some(iwg) => iwg,
                        _ => return bad_argument(req_id, json, "PublicIpId doesn't corespond to an existing id")
                    };
                    return bad_argument(req_id, json, "Sorry but UnlinkPublicIp with PublicIpId not yet supported")
                } else {
                    let id = require_arg!(in_json, "LinkPublicIpId");
                    let user = &mut main_json[user_id];

                    let link_idx = match user["LinkPublicIps"].members().position(|iwg| id == iwg["LinkPublicIpId"]) {
                        Some(iwg) => iwg,
                        _ => return bad_argument(req_id, json, "UnlinkPublicIpId doesn't corespond to an existing id")
                    };
                    let ip_id = user["LinkPublicIps"][link_idx]["PublicIpId"].clone();
                    let vm_id = user["LinkPublicIps"][link_idx]["VmIp"].clone();
                    if let Some(vm_idx) = user["Vms"].members().position(|vm| vm_id == vm["VmId"] ) {
                        let mut rng = thread_rng();
                        user["Vms"][vm_idx]["PublicIp"] = Ipv4Addr::from(rng.gen_range(0..std::u32::MAX)).to_string().into();
                    }

                    if let Some(ip_idx) = user["PublicIps"].members().position(|pip| ip_id == pip["PublicIpId"] ) {
                        user["PublicIps"][ip_idx].remove("VmId");
                        user["PublicIps"][ip_idx].remove("LinkPublicIpId");
                    }
                    user["LinkPublicIps"].array_remove(link_idx);
                }

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::UnlinkInternetService => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "UnlinkInternetService require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let id = require_arg!(in_json, "InternetServiceId");
                let net_id = require_arg!(in_json, "NetId");

                let net_idx = get_by_id!("Nets", "NetId", net_id);
                let user_iwgs = &mut main_json[user_id]["InternetServices"];
                let iwg = match user_iwgs.members_mut().find(|iwg| id == iwg["InternetServiceId"]) {
                    Some(iwg) => iwg,
                    _ => return bad_argument(req_id, json, "SecurityGroupId doesn't corespond to an existing id")
                };

                match net_idx {
                    Ok(_) => {iwg.remove("NetId")},
                    _ => return bad_argument(req_id, json, "Net not found")
                };
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteInternetService => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteInternetService require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let user_iwgs = &mut main_json[user_id]["InternetServices"];
                // TODO: check net is destroyable
                let id = require_arg!(in_json, "InternetServiceId");
                array_remove!(user_iwgs, |n| n["InternetServiceId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeletePublicIp => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeletePublicIp require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());
                let user_iwgs = &mut main_json[user_id]["PublicIps"];
                // TODO: check net is destroyable
                let id = require_arg!(in_json, "PublicIpId");
                array_remove!(user_iwgs, |n| n["PublicIpId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteNet => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteNet require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let user_nets = &mut main_json[user_id]["Nets"];
                // TODO: check net is destroyable
                let id = require_arg!(in_json, "NetId");
                array_remove!(user_nets, |n| n["NetId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadKeypairs => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadKeypairs require v4 signature")
                }

                let user_kps = &main_json[user_id]["Keypairs"];

                let mut kps = (*user_kps).clone();

                for k in kps.members_mut() {
                    k.remove("PrivateKey");
                }
                json["Keypairs"] = kps;

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadNets => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadNets require v4 signature")
                }

                let user_nets = &main_json[user_id]["Nets"];

                json["Nets"] = (*user_nets).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadAccessKeys => {
                json["AccessKeys"] = json::array![
                    json::object!{
                        State:"ACTIVE",
                        AccessKeyId: users[user_id]["access_key"].clone(),
                        CreationDate:"2020-01-28T10:58:41.000Z",
                        LastModificationDate:"2020-01-28T10:58:41.000Z"
                    }];

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadPublicCatalog => {

                json["Catalogs"] = json::array![
                    json::object!{
                        Entries: json::array![
                            json::object!{
                                Category: "Mecha",
                                Flags: "Red and Yellow",
                                Operation: "Explain in the Opening",
                                Service: "Protect Childs",
                                SubregionName: "univer",
                                Title: "イデオン",
                                Type: "Kyoshin",
                                UnitPrice: -1
                            }
                        ],
                        FromDate:"2020-01-28T10:58:41Z",
                        State: "CUR_ANT",
                        ToDate: "2019-08-24T14:15:22Z"
                    }];

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadPublicIpRanges  => {

                json["PublicIps"] = json::array![
                    "43.41.44.22/24",
                    "34.14.44.22/24"
                ];

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadRegions  => {

                json["Regions"] = json::array![
                    json::object!{
                        Endpoint: "127.0.0.1:3000",
                        RegionName: "mud-half-3"
                    }
                ];

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadSubregions  => {
                json["Subregions"] = json::array![
                    json::object!{
                        State: "available",
                        RegionName: "mud-half-3",
                        SubregionName: "mud-half-3a",
                        LocationCode: "PAR1"
                    },
                    json::object!{
                        State: "available",
                        RegionName: "mud-half-3",
                        SubregionName: "mud-half-3b",
                        LocationCode: "PAR1"
                    }
                ];
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadAccounts  => {
                let email = users[user_id]["login"].clone();

                json["Accounts"] =
                    json::array![
                        json::object!{
                            City:"カカリコ",
                            CompanyName: "plouf",
                            Country: "ハイラル",
                            CustomerId: user_id,
                            Email: match email.is_null() {
                                true => "RICOCHET_UNKNOW.???",
                                _ => email.as_str().unwrap()
                            },
                            FirstName: "oui",
                            JobTitle: "bu__3hit",
                            LastName: "non",
                            MobileNumber: "06 > 07",
                            PhoneNumber: "011 8 999 881 99 911 9 725...3",
                            StateProvince: "ok",
                            VatNumber: "the fuck ?",
                            ZipCode: "5"
                    }];

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadImages  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadImages require v4 signature")
                }

                let user_imgs = &main_json[user_id]["Images"];
                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalid JSON format")
                        },
                        Ok(in_json) => {
                            if in_json.has_key("Filters") {
                                let filters = &in_json["Filters"];
                                if !filters.is_object() {
                                    return bad_argument(req_id, json, "Filter must be an object :p")
                                }
                                json["Images"] = json::array!{};
                                for img in user_imgs.members() {
                                    let mut need_add = true;

                                    need_add = have_request_filter(filters, img,
                                                                   "ImageNames",
                                                                   "ImageName", need_add);

                                    need_add = have_request_filter(filters, img,
                                                                   "AccountAliases",
                                                                   "AccountAlias", need_add);
                                    if need_add {
                                        json["Images"].push((*img).clone()).unwrap();
                                    }
                                }
                            } else {
                                json["Images"] = (*user_imgs).clone();
                            }
                        }
                    }
                } else {
                    json["Images"] = (*user_imgs).clone();
                }

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadSecurityGroups  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadSecurityGroups require v4 signature")
                }

                let user_dl = &main_json[user_id]["SecurityGroups"];

                json["SecurityGroups"] = (*user_dl).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadDirectLinks  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadDirectLinks require v4 signature")
                }

                let user_dl = &main_json[user_id]["DirectLinks"];

                json["DirectLinks"] = (*user_dl).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::LinkVolume => {
                let in_json = require_in_json!(bytes);

                let device_name = require_arg!(in_json, "DeviceName");
                let vm_id = require_arg!(in_json, "VmId");
                let volume_id = require_arg!(in_json, "VolumeId");

                match get_by_id!("Vms", "VmId", vm_id) {
                    Ok((_, vm_idx)) => {
                        match get_by_id!("Volumes", "VolumeId", volume_id) {
                            Ok((_, vol_idx)) => {
                                let vol = &mut main_json[user_id]["Volumes"][vol_idx];
                                println!("link {:#}", vol.dump());
                                if vol["State"] != "available" && vol["State"] != "creating" {
                                    return bad_argument(req_id, json, "Volume not available")
                                }
                                vol["state"] = "in-use".into();
                                let vol_bsu = &mut main_json[user_id]["Vms"][vm_idx]["BlockDeviceMappings"];
                                vol_bsu.push(
                                    json::object!{
                                        DeviceName: device_name.clone(),
                                        Bsu: json::object!{
                                            VolumeId: volume_id.clone(),
                                            State: "attached",
                                            LinkDate: "2022-08-01T13:37:54.356Z",
                                            DeleteOnVmDeletion: false
                                        }
                                    }
                                ).unwrap();
                                main_json[user_id]["Volumes"][vol_idx]["LinkedVolumes"] =
                                    json::array![
                                        json::object!{
                                            "VolumeId": volume_id.clone(),
                                            "DeleteOnVmDeletion": false,
                                            "DeviceName": device_name.clone(),
                                            "State": "attached",
                                            "VmId": vm_id.clone()
                                        }
                                    ];
                            },
                            _ => return bad_argument(req_id, json, "Volume not found")
                        }
                    },
                    _ => return bad_argument(req_id, json, "VM not found")
                }

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteVolume => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteVolume require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                let user_nets = &mut main_json[user_id]["Volumes"];
                let id = require_arg!(in_json, "VolumeId");

                array_remove!(user_nets, |n| n["VolumeId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::UnlinkVolume => {
                let in_json = require_in_json!(bytes);

                let volume_id = require_arg!(in_json, "VolumeId");

                match get_by_id!("Volumes", "VolumeId", volume_id) {
                    Ok((_, vol_idx)) => {
                        let vol = &mut main_json[user_id]["Volumes"][vol_idx];
                        if vol["state"] != "in-use" {
                            return bad_argument(req_id, json, "Volume alerady unlink")
                        }
                        vol["state"] = "available".into();
                        let link_vol = &mut vol["LinkedVolumes"];
                        let vm_id = link_vol[0]["VmId"].to_string();
                        vol.remove("LinkedVolumes");
                        if let Ok((_, vm_idx)) = get_by_id!("Vms", "VmId", vm_id) {
                            let vol_bsu = &mut main_json[user_id]["Vms"][vm_idx]["BlockDeviceMappings"];
                            array_remove!(vol_bsu, |bsu| bsu["Bsu"]["VolumeId"] == volume_id);

                        };
                    },
                    _ => return bad_argument(req_id, json, "Volume not found")
                }
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateVolume => {
                let in_json = require_in_json!(bytes);

                let vol = json::object!{
                    VolumeId: format!("vol-{:08x}", req_id),
                    Tags: [],
                    VolumeType: optional_arg!(in_json, "VolumeType", "standard"),
                    SubregionName: require_arg!(in_json, "SubregionName"),
                    State: "creating",
                    CreationDate: "2010-10-01T12:34:56.789Z",
                    Iops: 100,
                    LinkedVolumes: [],
                    Size: optional_arg!(in_json, "Size", 10)
                };

                if !matches!(vol["VolumeType"].as_str().unwrap(), "io1" | "gp2" | "standard") {
                    return bad_argument(req_id, json, "Bad VolumeType");
                }
                main_json[user_id]["Volumes"].push(
                    vol.clone()).unwrap();
                json["Volume"] = vol;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadRouteTables  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadRouteTables require v4 signature")
                }

                let user_rts = &main_json[user_id]["RouteTables"];

                json["RouteTables"] = (*user_rts).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadSubnets  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadSubnets require v4 signature")
                }

                let user_rts = &main_json[user_id]["Subnets"];

                json["Subnets"] = (*user_rts).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadInternetServices  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadInternetServices require v4 signature")
                }

                let user_imgs = &main_json[user_id]["InternetServices"];

                json["InternetServices"] = (*user_imgs).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadPublicIps  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadPublicIps require v4 signature")
                }

                let user_imgs = &main_json[user_id]["PublicIps"];

                json["PublicIps"] = (*user_imgs).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadLinkPublicIps  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadLinkPublicIps require v4 signature")
                }

                let user_imgs = &main_json[user_id]["LinkPublicIps"];

                json["LinkPublicIps"] = (*user_imgs).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadTags  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadTags require v4 signature")
                }

                let user_imgs = &main_json[user_id]["Tags"];

                json["Tags"] = (*user_imgs).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadVolumes  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadVolumes require v4 signature")
                }
                let user_imgs = &mut main_json[user_id]["Volumes"];
                json["Volumes"] = (*user_imgs).clone();
                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Ok(in_json) => {

                            println!("{:#}", in_json.dump());
                            let filter = &in_json["Filters"];

                            json["Volumes"] = json::JsonValue::new_array();

                            for vol in user_imgs.members() {
                                let mut need_add = true;

                                need_add = have_request_filter(filter, vol,
                                                               "VolumeIds",
                                                               "VolumeId", need_add);
                                if need_add {
                                    json["Volumes"].push((*vol).clone()).unwrap();
                                }
                            }
                        },
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalid JSON format")
                        }
                    }
                }
                for vol in user_imgs.members_mut() {
                    if vol["State"] == "creating" {
                        vol["State"] = "available".into();
                    }
                }

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadLoadBalancers  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadLoadBalancers require v4 signature")
                }

                let user_vms = &main_json[user_id]["LoadBalancers"];

                json["LoadBalancers"] = (*user_vms).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadConsumptionAccount  => {
                println!("RicCall::ReadConsumptionAccount !!!");
                Ok((jsonobj_to_strret(json::object!{
                    ConsumptionEntries:
                    json::array!{
                        json::object!{
                            AccountId: format!("{:08x}", user_id),
                            Value: 0
                        }
                    }
                }, req_id), StatusCode::OK))
            },
            RicCall::ReadFlexibleGpus  => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadFlexibleGpus require v4 signature")
                }

                let user_fgpus = &mut main_json[user_id]["FlexibleGpus"];

                for fgpu in user_fgpus.members_mut() {
                    if fgpu["State"] == "detaching" {
                        fgpu["State"] = "allocated".into()
                    } else if fgpu["State"] == "attaching" {
                        fgpu["State"] = "attached".into()
                    }
                }
                json["FlexibleGpus"] = (*user_fgpus).clone();

                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Ok(in_json) => {
                            if in_json.has_key("Filters") {
                                let filter = &in_json["Filters"];

                                json["FlexibleGpus"] = json::JsonValue::new_array();

                                for fgpu in user_fgpus.members() {
                                    let mut need_add = true;

                                    need_add = have_request_filter(filter, fgpu,
                                                                   "FlexibleGpuIds",
                                                                   "FlexibleGpuId", need_add);
                                    if need_add {
                                        json["FlexibleGpus"].push((*fgpu).clone()).unwrap();
                                    }
                                }
                            }
                        },
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalid JSON format")
                        }
                    }
                }
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadApiAccessPolicy => {
                json["ApiAccessPolicy"] = json::object!{
                    "RequireTrustedEnv": false,
                    "MaxAccessKeyExpirationSeconds": 0
                };
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateKeypair => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateKeypair require v4 signature")
                }
                let mut kp = json::object!{};
                match json::parse(std::str::from_utf8(&bytes).unwrap()) {
                    Ok(in_json) => {
                        if in_json.has_key("KeypairName") {
                            let name = in_json["KeypairName"].to_string();
                            check_conflict!(Keypair, name, json);
                            kp["KeypairName"] = json::JsonValue::String(name);

                            let rsa = Rsa::generate(4096).unwrap();
                            let private_key = rsa.clone().private_key_to_der().unwrap();
                            let pkey = PKey::from_rsa(rsa).unwrap();
                            let pkey_ref = pkey.deref();
                            let mut x509builder = X509Builder::new().unwrap();
                            match x509builder.set_pubkey(pkey_ref) {
                                Ok(()) => (),
                                _ => {
                                    return serv_error(req_id, json, "fail to generate fingerprint (0)")
                                }
                            }
                            match x509builder.sign(pkey_ref, MessageDigest::md5()) {
                                Ok(()) => (),
                                _ => {
                                    return serv_error(req_id, json, "fail to generate fingerprint (1)")
                                }
                            }
                            let x509 = x509builder.build();

                            let digest = x509.digest(MessageDigest::md5()).unwrap();
                            let mut digest_str = String::with_capacity(3 * digest.len());
                            let mut first_byte = true;
                            #[allow(clippy::unnecessary_to_owned)]
                            for byte in digest.to_vec() {
                                if !first_byte {
                                    write!(digest_str, ":").unwrap();
                                }
                                write!(digest_str, "{:02x}", byte).unwrap();
                                first_byte = false;
                            }
                            kp["KeypairFingerprint"] = json::JsonValue::String(digest_str);

                            let private_pem = Pem::new("PRIVATE KEY", private_key);
                            let private = encode_config(&private_pem, EncodeConfig { line_ending: LineEnding::LF });

                            kp["PrivateKey"] = json::JsonValue::String(private);
                        } else {
                            return bad_argument(req_id, json, "KeypairName Missing")
                        }
                    },
                    Err(_) => {
                        return bad_argument(req_id, json, "Invalid JSON format")
                    }
                }
                main_json[user_id]["Keypairs"].push(
                    kp.clone()).unwrap();
                json["Keypair"] = kp;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteSecurityGroup => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteSecurityGroupRule require v4 signature")
                }

                let in_json = require_in_json!(bytes);
                let user_sgs = &mut main_json[user_id]["SecurityGroups"];

                let id = optional_arg!(in_json, "SecurityGroupId", -1);
                if id == -1 {
                    let name = optional_arg!(in_json, "SecurityGroupName", -1);

                    if name == -1 {
                        return bad_argument(req_id, json, "either SecurityGroupId or SecurityGroupName is require")
                    }
                    array_remove!(user_sgs, |sg| sg["SecurityGroupName"] == name);
                } else {
                    array_remove!(user_sgs, |sg| sg["SecurityGroupId"] == id);
                }
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteSecurityGroupRule => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteSecurityGroupRule require v4 signature")
                }

                let in_json = require_in_json!(bytes);
                println!("DeleteSecurityGroupRule: {:#}", in_json.dump());
                let flow = match require_arg!(in_json, "Flow").as_str() {
                    Some(s) => match s {
                        "Inbound" => true,
                        "Outbound" => false,
                        _ => return bad_argument(req_id, json, "The direction of the flow must be `Inbound` or `Outbound`.")
                    },
                    _ => return bad_argument(req_id, json, "Flow must be a string")
                };
                let sg_id = require_arg!(in_json, "SecurityGroupId");
                let user_sgs = &mut main_json[user_id]["SecurityGroups"];
                let sg = match user_sgs.members_mut().find(|sg| sg_id == sg["SecurityGroupId"]) {
                    Some(sg) => sg,
                    _ => return bad_argument(req_id, json, "SecurityGroupId doesn't corespond to an existing id")
                };

                fn rm_rule(json : json::JsonValue, sg: &mut json::JsonValue,
                           pr : & json::JsonValue, flow: bool, req_id: usize) ->
                    Result<(String, hyper::StatusCode), (String, hyper::StatusCode)> {

                    let new_rule = json::object!{
                        "FromPortRange": require_arg_2!(json, req_id, pr, "FromPortRange"),
                        "IpProtocol": optional_arg!(pr, "IpProtocol", "-1"),
                        "ToPortRange":2222,
                        "IpRanges":[
                            "unimplemented"
                        ]
                    };
                    array_remove_2!(json, req_id, sg[flow_to_str!(flow)],
                                  |other_rule| is_same_rule(&new_rule, other_rule));

                    Ok(("unused".into(), StatusCode::OK))
                }

                if in_json.has_key("Rules") {
                    for r in in_json["Rules"].members() {
                        rm_rule(json.clone(), sg, r, flow, req_id)?;
                    }
                } else {
                    rm_rule(json.clone(), sg, &in_json, flow, req_id)?;
                }
                json["SecurityGroup"] = sg.clone();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateDirectLink => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadDirectLinks require v4 signature")
                }

                let in_json = require_in_json!(bytes);

                let dl = json::object!{
                    AccountId: format!("{:08x}", user_id),
                    Bandwidth: require_arg!(in_json, "Bandwidth"),
                    DirectLinkId: format!("dxcon-{:08x}", req_id),
                    DirectLinkName: require_arg!(in_json, "DirectLinkName"),
                    "Location": "PAR1",
                    "RegionName": "eu-west-2",
                    "State": "requested"
                };
                if dl["Bandwidth"] != "1Gbps" && dl["Bandwidth"] != "10Gbps" {
                    return bad_argument(req_id, json, "Bandwidth need to be either '1Gbps' or '10Gbps'")
                }
                main_json[user_id]["DirectLinks"].push(
                    dl.clone()).unwrap();
                json["DirectLink"] = dl;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreatePublicIp => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateSecurityGroupRule require v4 signature")
                }
                let mut rng = thread_rng();
                let eip = json::object!{
                    PublicIpId: format!("eipalloc-{:08x}", req_id),
                    Tags: json::array!{},
                    PublicIp: Ipv4Addr::from(rng.gen_range(0..std::u32::MAX)).to_string()
                };

                main_json[user_id]["PublicIps"].push(
                    eip.clone()).unwrap();
                json["PublicIp"] = eip;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateInternetService => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateSecurityGroupRule require v4 signature")
                }
                let igw = json::object!{
                    InternetServiceId: format!("igw-{:08x}", req_id),
                    Tags: json::array!{},
                };

                main_json[user_id]["InternetServices"].push(
                    igw.clone()).unwrap();
                json["InternetService"] = igw;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateSecurityGroupRule => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateSecurityGroupRule require v4 signature")
                }

                let in_json = require_in_json!(bytes);
                println!("CreateSecurityGroupRule: {:#}", in_json.dump());
                let sg_id = match in_json.has_key("SecurityGroupId") {
                    true => in_json["SecurityGroupId"].clone(),
                    _ => return bad_argument(req_id, json, "SecurityGroupId required")
                };
                let user_sgs = &mut main_json[user_id]["SecurityGroups"];
                let sg = match user_sgs.members_mut().find(|sg| sg_id == sg["SecurityGroupId"]) {
                    Some(sg) => sg,
                    _ => return bad_argument(req_id, json, "SecurityGroupId doesn't corespond to an existing id")
                };
                let flow = match in_json.has_key("Flow") {
                    true => match in_json["Flow"].as_str() {
                        Some(s) => match s {
                            "Inbound" => true,
                            "Outbound" => false,
                            _ => return bad_argument(req_id, json, "The direction of the flow must be `Inbound` or `Outbound`.")
                        },
                        _ => return bad_argument(req_id, json, "Flow should be a string")
                    },
                    _ => return bad_argument(req_id, json, "Flow required")
                };

                fn add_rule(json : json::JsonValue, sg: &mut json::JsonValue,
                            pr : & json::JsonValue, flow: bool, req_id: usize) ->
                    Result<(String, hyper::StatusCode), (String, hyper::StatusCode)>  {
                        let new_rule = json::object!{
                            "FromPortRange": require_arg_2!(json , req_id, pr, "FromPortRange"),
                            "IpProtocol": optional_arg!(pr, "IpProtocol", "-1"),
                            "ToPortRange":2222,
                            "IpRanges":[
                                "unimplemented"
                            ]
                        };

                        if sg[flow_to_str!(flow)].members().any(|other_rule| is_same_rule(&new_rule, other_rule)) {
                            return bad_argument(req_id, json, "rule alerady exist");
                        }
                        // should check that the rule can be an outbound rule
                        sg[flow_to_str!(flow)].push(new_rule).unwrap();
                        Ok(("unused".into(), StatusCode::OK))
                    }

                if in_json.has_key("Rules") {
                    for r in in_json["Rules"].members() {
                        add_rule(json.clone(), sg, r, flow, req_id)?;
                    }
                } else {
                    add_rule(json.clone(), sg, &in_json, flow, req_id)?;
                }
                json["SecurityGroup"] = sg.clone();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            }
            RicCall::CreateSecurityGroup => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateImage require v4 signature")
                }
                let sg_id = format!("sg-{:08x}", req_id);
                let in_json = require_in_json!(bytes);
                let mut sg = json::object!{
                    Tags: json::array!{},
                    SecurityGroupId: sg_id,
                    AccountId: format!("{:08x}", user_id),
                    OutboundRules: json::array!{},
                    InboundRules: json::array!{},
                    SecurityGroupName: require_arg!(in_json, "SecurityGroupName"),
                    Description: require_arg!(in_json, "Description"),
                };

                if in_json.has_key("NetId") {
                    let net_id = in_json["NetId"].clone();
                    let user_nets = &mut main_json[user_id]["Nets"];
                    match user_nets.members().position(|net| net_id == net["NetId"]) {
                        Some(_idx) => { sg["NetId"] = net_id },
                        _ => return bad_argument(req_id, json, "NetId doesn't corespond to a net id")
                    }
                }

                main_json[user_id]["SecurityGroups"].push(
                    sg.clone()).unwrap();
                json["SecurityGroup"] = sg;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadAdminPassword => {
                let in_json = require_in_json!(bytes);
                let vm_id = require_arg!(in_json, "VmId");
                json["VmId"] = vm_id;
                json["AdminPassword"] = "w0l0l0".into();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::UpdateVm => {
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());
                let vm_id = require_arg!(in_json, "VmId");
                json["ricochet-info"] = format!("vm id: {}, but update vm not implemented", vm_id).into();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateVms => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateVms require v4 signature")
                }
                let vm_id = format!("i-{:08x}", req_id);
                let in_json = match json::parse(std::str::from_utf8(&bytes).unwrap()) {
                    Ok(in_json) => in_json,
                    Err(_) => {
                        json::object!{}
                    }
                };

                // {"BootOnCreation":true,"DeletionProtection":false,"ImageId":"ami-cd8d714e","KeypairName":"deployer","MaxVmsCount":1,"MinVmsCount":1,"NestedVirtualization":false,"SecurityGroupIds":["sg-ffffff00"],"SubnetId":"subnet-00000008","VmType":"tinav4.c1r1p2"}
                println!("{:#}", in_json.dump());
                let vm = json::object!{
                    VmType: optional_arg!(in_json, "VmType", "small"),
                    "VmInitiatedShutdownBehavior": "stop",
                    "State": "running",
                    "StateReason": "",
                    "RootDeviceType": "ebs",
                    "RootDeviceName": "/dev/sda1",
                    "IsSourceDestChecked": true,
                    "KeypairName": "my_craft",
                    "PublicIp": "100.200.60.100",
                    ImageId: optional_arg!(in_json, "ImageId", "ami-00000000"),
                    "PublicDnsName": "ows-148-253-69-185.eu-west-2.compute.outscale.com",
                    "DeletionProtection": false,
                    "Architecture": "x86_64",
                    "NestedVirtualization": false,
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/sda1",
                            "Bsu": {
                                "VolumeId": "vol-6ce9a61e",
                                "State": "attached",
                                "LinkDate": "2022-08-01T13:37:54.356Z",
                                "DeleteOnVmDeletion": true
                            }
                        }
                    ],
                    VmId: vm_id,
                    "ReservationId": "r-a3df6a95",
                    "Hypervisor": "xen",
                    "Placement": {
                        "Tenancy": "default",
                        "SubregionName": "mud-half-3a"
                    },
                    "ProductCodes": [
                        "0001"
                    ],
                    "CreationDate": "2022-08-01T13:37:54.356Z",
                    "UserData": "",
                    "PrivateIp": "10.0.00.0",
                    "SecurityGroups": [
                        {
                            "SecurityGroupName": "default",
                            "SecurityGroupId": "sg-d56a6db7"
                        }
                    ],
                    "BsuOptimized": false,
                    "LaunchNumber": 0,
                    "Performance": "high",
                    "Tags": [],
                    "PrivateDnsName": "ip-10-8-41-9.eu-west-2.compute.internal"
                };

                main_json[user_id]["Vms"].push(
                    vm.clone()).unwrap();
                json["Vms"] = json::array!{vm};
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateTags|RicCall::DeleteTags => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateTags/DeleteTags require v4 signature")
                }
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());
                if !in_json.has_key("Tags") && !in_json.has_key("ResourceIds") {
                    return bad_argument(req_id, json, "CreateTags/DeleteTags require: ResourceIds, Tags argument");
                }

                let tags = &in_json["Tags"];

                for t in tags.members() {
                    require_arg!(t, "Key");
                    require_arg!(t, "Value");
                }

                let mut ids = Vec::new();
                let resources_todo = in_json["ResourceIds"].members().map(|id| {
                    ids.push(id.clone());
                    match id.as_str() {
                        Some(id) => match id.split_once('-') {
                            Some((t, _)) => match t {
                                "sg" => get_by_id!("SecurityGroups", "SecurityGroupId", id),
                                "i" => get_by_id!("Vms", "VmId", id),
                                "ami" => get_by_id!("Images", "ImageId", id),
                                "vol" => get_by_id!("Volumes", "VolumeId", id),
                                "fgpu" => get_by_id!("FlexibleGpus", "FlexibleGpuId", id),
                                "vpc" => get_by_id!("Nets", "NetId", id),
                                _ => Err(bad_argument(req_id, json.clone(), "invalide resource id"))
                            },
                            _ => Err(bad_argument(req_id, json.clone(), "invalide resource id"))
                        },
                        _ => Err(bad_argument(req_id, json.clone(), "invalide resource id"))
                    }
                }).collect::<Result<Vec<_>, _>>();

                let resources_todo = match resources_todo {
                    Ok(ok) => ok,
                    Err(e) => return e
                };
                let user_main_json = &mut main_json[user_id];

                for (resource_t_idx, id) in zip(resources_todo, ids) {
                    let (resource_t, idx) = resource_t_idx;
                    for tag in tags.members() {
                        let mut ntag = (*tag).clone();

                        ntag["ResourceId"] = id.clone();
                        ntag["ResourceType"] = resource_t.to_string().into();

                        match *self {
                            RicCall::CreateTags => {
                                user_main_json["Tags"].push(ntag).unwrap();
                                user_main_json[resource_t][idx]["Tags"].push((*tag).clone()).unwrap();
                            },
                            RicCall::DeleteTags => {
                                array_remove!(user_main_json["Tags"], |ot| ntag.eq(ot));
                                array_remove!(user_main_json[resource_t][idx]["Tags"], |ot| tag.eq(ot));
                            },
                            _ => todo!()
                        };
                    }
                }
                println!("CreateTags");
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadQuotas => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadQuotas require v4 signature")
                }
                json["QuotaTypes"] = json::array![
                    json::object!{
                        Quotas: json::array![
                            json::object!{
                                ShortDescription: "VM Limit",
                                QuotaCollection: "Compute",
                                AccountId: format!("{:08x}", user_id),
                                Description: "Maximum number of VM this user can own",
                                MaxValue: "not implemented",
                                UsedValue: "not implemented",
                                Name: "bypass_group_size_limit"
                            },
                            json::object!{
                                ShortDescription: "Bypass Group Size Limit",
                                QuotaCollection: "Other",
                                AccountId: format!("{:08x}", user_id),
                                Description: "Maximum size of a bypass group",
                                MaxValue: "not implemented",
                                UsedValue: "not implemented",
                                Name: "bypass_group_size_limit"
                            }
                        ],
                        QuotaType: "global"
                    }];
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteFlexibleGpu => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteFlexibleGpu require v4 signature")
                }
                let user_fgpu = &mut main_json[user_id]["FlexibleGpus"];
                let in_json = require_in_json!(bytes);
                let id = require_arg!(in_json, "FlexibleGpuId");

                array_remove!(user_fgpu, |fgpu| id == fgpu["FlexibleGpuId"]);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteDirectLink => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "DeleteDirectLink require v4 signature")
                }
                let user_fgpu = &mut main_json[user_id]["DirectLinks"];
                let in_json = require_in_json!(bytes);
                let id = require_arg!(in_json, "DirectLinkId");

                array_remove!(user_fgpu, |fgpu| id == fgpu["DirectLinkId"]);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateFlexibleGpu => {
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "CreateFlexibleGpu require v4 signature")
                }
                let user_fgpu = &mut main_json[user_id]["FlexibleGpus"];
                let in_json = require_in_json!(bytes);
                let model_name = require_arg!(in_json, "ModelName");
                let subregion_name = require_arg!(in_json, "SubregionName");
                let generation = optional_arg!(in_json, "Generation", "v3");
                let delete_on_vmd_eletion = optional_arg!(in_json, "DeleteOnVmDeletion", false);

                let fgpu_json = json::object!{
                    DeleteOnVmDeletion: delete_on_vmd_eletion,
                    FlexibleGpuId: format!("fgpu-{:08x}", req_id),
                    Generation: generation,
                    ModelName: model_name,
                    Tags: json::array!{},
                    State: "allocated",
                    SubregionName: subregion_name,
                };


                println!("CreateFlexibleGpu {:#}", fgpu_json.dump());
                json["FlexibleGpu"] = fgpu_json.clone();
                user_fgpu.push(fgpu_json).unwrap();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            }
        }
    }
}


impl FromStr for RicCall {
    type Err = ();
    fn from_str(path: &str) -> Result<Self, Self::Err> {
        println!("{}", path);
        let ps = remove_duplicate_slashes(path);
        let p = ps.as_str();

        println!("{}", p);
        match p {
            "/" => Ok(RicCall::Root),
            "/CreateKeypair" | "/api/v1/CreateKeypair" | "/api/latest/CreateKeypair" =>
                Ok(RicCall::CreateKeypair),
            "/ReadKeypairs" | "/api/v1/ReadKeypairs" | "/api/latest/ReadKeypairs" =>
                Ok(RicCall::ReadKeypairs),
            "/ReadAdminPassword" | "/api/v1/ReadAdminPassword" | "/api/latest/ReadAdminPassword" =>
                Ok(RicCall::ReadAdminPassword),
            "/DeleteKeypair" | "/api/v1/DeleteKeypair" | "/api/latest/DeleteKeypair" =>
                Ok(RicCall::DeleteKeypair),
            "/ReadAccessKeys" | "/api/v1/ReadAccessKeys" | "/api/latest/ReadAccessKeys" =>
                Ok(RicCall::ReadAccessKeys),
            "/ReadVms" | "/api/v1/ReadVms" | "/api/latest/ReadVms" =>
                Ok(RicCall::ReadVms),
            "/CreateVms" | "/api/v1/CreateVms" | "/api/latest/CreateVms" =>
                Ok(RicCall::CreateVms),
            "/CreateSecurityGroup" | "/api/v1/CreateSecurityGroup" | "/api/latest/CreateSecurityGroup" =>
                Ok(RicCall::CreateSecurityGroup),
            "/CreateSecurityGroupRule" | "/api/v1/CreateSecurityGroupRule" | "/api/latest/CreateSecurityGroupRule" =>
                Ok(RicCall::CreateSecurityGroupRule),
            "/CreateDirectLink" | "/api/v1/CreateDirectLink" | "/api/latest/CreateDirectLink" =>
                Ok(RicCall::CreateDirectLink),
            "/CreateInternetService" | "/api/v1/CreateInternetService" | "/api/latest/CreateInternetService" =>
                Ok(RicCall::CreateInternetService),

            "/LinkInternetService" | "/api/v1/LinkInternetService" | "/api/latest/LinkInternetService" =>
                Ok(RicCall::LinkInternetService),
            "/UnlinkInternetService" | "/api/v1/UnlinkInternetService" | "/api/latest/UnlinkInternetService" =>
                Ok(RicCall::UnlinkInternetService),
            "/LinkPublicIp" | "/api/v1/LinkPublicIp" | "/api/latest/LinkPublicIp" =>
                Ok(RicCall::LinkPublicIp),
            "/UnlinkPublicIp" | "/api/v1/UnlinkPublicIp" | "/api/latest/UnlinkPublicIp" =>
                Ok(RicCall::UnlinkPublicIp),

            "/LinkFlexibleGpu" | "/api/v1/LinkFlexibleGpu" | "/api/latest/LinkFlexibleGpu" =>
                Ok(RicCall::LinkFlexibleGpu),

            "/UnlinkFlexibleGpu" | "/api/v1/UnlinkFlexibleGpu" | "/api/latest/UnlinkFlexibleGpu" =>
                Ok(RicCall::UnlinkFlexibleGpu),

            "/CreatePublicIp" | "/api/v1/CreatePublicIp" | "/api/latest/CreatePublicIp" =>
                Ok(RicCall::CreatePublicIp),


            "/DeleteInternetService" | "/api/v1/DeleteInternetService" | "/api/latest/DeleteInternetService" =>
                Ok(RicCall::DeleteInternetService),
            "/DeletePublicIp" | "/api/v1/DeletePublicIp" | "/api/latest/DeletePublicIp" =>
                Ok(RicCall::DeletePublicIp),
            "/DeleteVms" | "/api/v1/DeleteVms" | "/api/latest/DeleteVms" =>
                Ok(RicCall::DeleteVms),
            "/StopVms" | "/api/v1/StopVms" | "/api/latest/StopVms" =>
                Ok(RicCall::StopVms),
            "/StartVms" | "/api/v1/StartVms" | "/api/latest/StartVms" =>
                Ok(RicCall::StartVms),
            "/DeleteLoadBalancer" | "/api/v1/DeleteLoadBalancer" | "/api/latest/DeleteLoadBalancer" =>
                Ok(RicCall::DeleteLoadBalancer),
            "/DeleteDirectLink" | "/api/v1/DeleteDirectLink" | "/api/latest/DeleteDirectLink" =>
                Ok(RicCall::DeleteDirectLink),
            "/DeleteSecurityGroup" | "/api/v1/DeleteSecurityGroup" | "/api/latest/DeleteSecurityGroup" =>
                Ok(RicCall::DeleteSecurityGroup),
            "/DeleteSecurityGroupRule" | "/api/v1/DeleteSecurityGroupRule" | "/api/latest/DeleteSecurityGroupRule" =>
                Ok(RicCall::DeleteSecurityGroupRule),

            "/DeleteTags" | "/api/v1/DeleteTags" | "/api/latest/DeleteTags" =>
                Ok(RicCall::DeleteTags),

            "/ReadFlexibleGpus" |"/api/v1/ReadFlexibleGpus" | "/api/latest/ReadFlexibleGpus" =>
                Ok(RicCall::ReadFlexibleGpus),
            "/ReadConsumptionAccount" |"/api/v1/ReadConsumptionAccount" | "/api/latest/ReadConsumptionAccount" =>
                Ok(RicCall::ReadConsumptionAccount),
            "/CreateTags" | "/api/v1/CreateTags" | "/api/latest/CreateTags" =>
                Ok(RicCall::CreateTags),
            "/ReadTags" | "/api/v1/ReadTags" | "/api/latest/ReadTags" =>
                Ok(RicCall::ReadTags),
            "/CreateFlexibleGpu" | "/api/v1/CreateFlexibleGpu" | "/api/latest/CreateFlexibleGpu" =>
                Ok(RicCall::CreateFlexibleGpu),
            "/DeleteFlexibleGpu" | "/api/v1/DeleteFlexibleGpu" | "/api/latest/DeleteFlexibleGpu" =>
                Ok(RicCall::DeleteFlexibleGpu),
            "/CreateImage" | "/api/v1/CreateImage" | "/api/latest/CreateImage" =>
                Ok(RicCall::CreateImage),
            "/CreateLoadBalancer" | "/api/v1/CreateLoadBalancer" | "/api/latest/CreateLoadBalancer" =>
                Ok(RicCall::CreateLoadBalancer),
            "/ReadAccounts" | "/api/v1/ReadAccounts" | "/api/latest/ReadAccounts" =>
                Ok(RicCall::ReadAccounts),
            "/ReadImages" | "/api/v1/ReadImages" | "/api/latest/ReadImages" =>
                Ok(RicCall::ReadImages),
            "/ReadDirectLinks" | "/api/v1/ReadDirectLinks" | "/api/latest/ReadDirectLinks" =>
                Ok(RicCall::ReadDirectLinks),
            "/ReadSecurityGroups" | "/api/v1/ReadSecurityGroups" | "/api/latest/ReadSecurityGroups" =>
                Ok(RicCall::ReadSecurityGroups),
            "/ReadVolumes" | "/api/v1/ReadVolumes" | "/api/latest/ReadVolumes" =>
                Ok(RicCall::ReadVolumes),
            "/CreateVolume" | "/api/v1/CreateVolume" | "/api/latest/CreateVolume" =>
                Ok(RicCall::CreateVolume),
            "/DeleteVolume" | "/api/v1/DeleteVolume" | "/api/latest/DeleteVolume" =>
                Ok(RicCall::DeleteVolume),
            "/ReadLoadBalancers" | "/api/v1/ReadLoadBalancers" | "/api/latest/ReadLoadBalancers" =>
                Ok(RicCall::ReadLoadBalancers),
            "/ReadApiAccessPolicy" | "/api/v1/ReadApiAccessPolicy" | "/api/latest/ReadApiAccessPolicy" =>
                Ok(RicCall::ReadApiAccessPolicy),
            "/ReadPublicCatalog" | "/api/v1/ReadPublicCatalog" | "/api/latest/ReadPublicCatalog" =>
                Ok(RicCall::ReadPublicCatalog),
            "/ReadRegions" | "/api/v1/ReadRegions" | "/api/latest/ReadRegions" =>
                Ok(RicCall::ReadRegions),
            "/ReadSubregions" | "/api/v1/ReadSubregions" | "/api/latest/ReadSubregions" =>
                Ok(RicCall::ReadSubregions),
            "/ReadPublicIpRanges" | "/api/v1/ReadPublicIpRanges" | "/api/latest/ReadPublicIpRanges" =>
                Ok(RicCall::ReadPublicIpRanges),
            "/ReadQuotas" | "/api/v1/ReadQuotas" | "/api/latest/ReadQuotas" =>
                Ok(RicCall::ReadQuotas),
            "/ReadNets" | "/api/v1/ReadNets" | "/api/latest/ReadNets" =>
                Ok(RicCall::ReadNets),
            "/ReadInternetServices" | "/api/v1/ReadInternetServices" | "/api/latest/ReadInternetServices" =>
                Ok(RicCall::ReadInternetServices),
            "/ReadPublicIps" | "/api/v1/ReadPublicIps" | "/api/latest/ReadPublicIps" =>
                Ok(RicCall::ReadPublicIps),
            "/ReadLinkPublicIps" | "/api/v1/ReadLinkPublicIps" | "/api/latest/ReadLinkPublicIps" =>
                Ok(RicCall::ReadLinkPublicIps),
            "/CreateNet" | "/api/v1/CreateNet" | "/api/latest/CreateNet" =>
                Ok(RicCall::CreateNet),
            "/DeleteNet" | "/api/v1/DeleteNet" | "/api/latest/DeleteNet" =>
                Ok(RicCall::DeleteNet),
            "/DeleteSubnet" | "/api/v1/DeleteSubnet" | "/api/latest/DeleteSubnet" =>
                Ok(RicCall::DeleteSubnet),
            "/CreateSubnet" | "/api/v1/CreateSubnet" | "/api/latest/CreateSubnet" =>
                Ok(RicCall::CreateSubnet),
            "/ReadSubnets" | "/api/v1/ReadSubnets" | "/api/latest/ReadSubnets" =>
                Ok(RicCall::ReadSubnets),

            "/CreateRouteTable" | "/api/v1/CreateRouteTable" | "/api/latest/CreateRouteTable" =>
                Ok(RicCall::CreateRouteTable),
            "/DeleteRouteTable" | "/api/v1/DeleteRouteTable" | "/api/latest/DeleteRouteTable" =>
                Ok(RicCall::DeleteRouteTable),
            "/LinkRouteTable" | "/api/v1/LinkRouteTable" | "/api/latest/LinkRouteTable" =>
                Ok(RicCall::LinkRouteTable),
            "/LinkVolume" | "/api/v1/LinkVolume" | "/api/latest/LinkVolume" =>
                Ok(RicCall::LinkVolume),
            "/UnlinkVolume" | "/api/v1/UnlinkVolume" | "/api/latest/UnlinkVolume" =>
                Ok(RicCall::UnlinkVolume),
            "/UnlinkRouteTable" | "/api/v1/UnlinkRouteTable" | "/api/latest/UnlinkRouteTable" =>
                Ok(RicCall::UnlinkRouteTable),
            "/ReadRouteTables" | "/api/v1/ReadRouteTables" | "/api/latest/ReadRouteTables" =>
                Ok(RicCall::ReadRouteTables),
            "/CreateRoute" | "/api/v1/CreateRoute" | "/api/latest/CreateRoute" =>
                Ok(RicCall::CreateRoute),

            "/UpdateVm" | "/api/v1/UpdateVm" | "/api/latest/UpdateVm" =>
                Ok(RicCall::UpdateVm),

            "/DeleteRoute" | "/api/v1/DeleteRoute" | "/api/latest/DeleteRoute" =>
                Ok(RicCall::DeleteRoute),

            "/debug" => Ok(RicCall::Debug),
            _ => Err(())
        }
    }
}

fn which_v4_to_date(which_v4: & String) -> &str
{
    if which_v4 == "OSC4" {
        return "X-Osc-Date"
    } else if which_v4 == "AWS4" {
        return "X-Amz-Date"
    }
    "X-Unknow-Date"
}

fn clasify_v4(userpass: & str) ->  Option<(&str, String)>
{
    let which: String;

    if userpass.starts_with("OSC4") {
        which = "OSC4".to_string();
    } else if userpass.starts_with("AWS4") {
        which = "AWS4".to_string();
    } else {
        return None
    }

    Some((userpass.strip_prefix(format!("{}-HMAC-SHA256 ", which).as_str()).unwrap(), which))
}

fn v4_error_ret(error_msg: &mut String, error:  &str) -> bool
{
    *error_msg = "v4 error: ".to_string();
    error_msg.push_str(error);
    false
}

// connection: sqlite::Connection , connection: & sqlite::ConnectionWithFullMutex
async fn handler(req: Request<Body>,
                 connection: & Arc<futures::lock::Mutex<json::JsonValue>>,
                 req_id: usize,
                 cfg: & Arc<futures::lock::Mutex<json::JsonValue>>)
                 -> Result<Response<Body>, Infallible> {
    let main_json = connection.lock().await;
    let cfg = cfg.lock().await;
    let method = req.method().clone();
    let headers = req.headers().clone();
    let mut user_id = 0;
    let uri = req.uri().clone();
    let mut bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let users = &cfg["users"];
    let mut out_convertion = false;
    let mut api = "api".to_string();
    let mut auth = AuthType::None;

    println!("in handler");

    if cfg["auth_type"] != "none" {
        let mut response = Response::new(Body::empty());

        let auth_type = match cfg["auth_type"].as_str().unwrap() {
            "exist" => 0,
            "headarches" => 1,
            _ => -1
        };
        let userpass = match headers.get("Authorization") {
            Some(auth) => {
                auth.to_str().unwrap().to_string()
            }
            _ =>  {
                "".to_string()
            }
        };
        let mut error_msg = "\"Unknow user\"".to_string();
        let cred = clasify_v4(&userpass);

        //println!("headers: ===|{:?}|===", headers);
        //println!("userpass: ===|{}|===", userpass);
        if userpass.starts_with("Basic ") {
            let based = userpass.strip_prefix("Basic ").unwrap();
            let decoded = general_purpose::STANDARD
                .decode(based).unwrap();
            let stringified = std::str::from_utf8(&decoded).unwrap();
            let (login, password) = stringified.split_once(':').unwrap();

            if let Some(idx) = users.members().position(|u| {
                let ret = u["login"] == login;
                if auth_type < 1 {
                    return ret;
                }
                u["pass"] == password
            }) {
                user_id = idx;
                auth = match cfg["password_as_ak"] == true {
                    true => AuthType::AkSk,
                    _ => AuthType::Basic,
                };
            }
        } else if cred.is_some() {
            let cred = cred.unwrap();
            let which_v4 = cred.1;
            let cred = match cred.0.strip_prefix("Credential=") {
                Some(v) => v,
                _ =>  return bad_auth("\"Authorization Header is broken, should start witgh 'Credential='\"".to_string())
            };
            let tuple_cred = match cred.split_once('/') {
                Some((v, other)) => (v, other),
                _ =>  return bad_auth("\"Authorization Header is broken, can't find ACCESS_KEY\"".to_string())
            };
            let ak = tuple_cred.0;
            let cred = tuple_cred.1;
            println!("{}", cred);
            match users.members().position(|u| {
                let ret = u["access_key"] == ak;

                if !ret {
                    return false
                }

                let x_date = match headers.get(which_v4_to_date(&which_v4)) {
                    Some(x_date) => {
                        x_date.to_str().unwrap().to_string()
                    }
                    _ =>  {
                        println!("Date hdr not found");
                        return v4_error_ret(&mut error_msg, "Date hdr not found");
                    }
                };
                let host = match headers.get("Host") {
                    Some(host) => {
                        host.to_str().unwrap().to_string()
                    }
                    _ => return v4_error_ret(&mut error_msg, "Host not found")
                };
                let short_date = &x_date[..8];
                let cred = match cred.strip_prefix(format!("{}/", short_date).as_str()) {
                    Some(v) => v,
                    _ => return false
                };

                let tuple_cred = match cred.split_once('/') {
                    Some((v, other)) => (v, other),
                    _ =>  return v4_error_ret(&mut error_msg, "missing '/'")
                };
                let region = tuple_cred.0;
                let cred = tuple_cred.1;

                let tuple_cred = match cred.split_once('/') {
                    Some((v, other)) => (v, other),
                    _ =>  return v4_error_ret(&mut error_msg, "missing '/'")
                };
                api = tuple_cred.0.to_string();
                let cred = tuple_cred.1;

                let tuple_cred = match cred.split_once(',') {
                    Some((_, sc)) =>
                        match sc.strip_prefix(" SignedHeaders=") {
                            Some(v) => match v.split_once(',') {
                                Some((v0,v1)) => (v0,v1),
                                _ => return v4_error_ret(&mut error_msg, "missing ','")
                            },
                            _ => return v4_error_ret(&mut error_msg, "missing 'SignedHeaders='")
                        },
                    _ => return v4_error_ret(&mut error_msg, "missing ','")
                };
                let signed_hdrs = tuple_cred.0;
                let cred = tuple_cred.1;
                let send_signature = match cred.strip_prefix(" Signature=") {
                    Some(sign) => sign,
                    _ => return v4_error_ret(&mut error_msg, "missing 'Signature='")
                };

                if auth_type < 1 {
                    return ret;
                }

                let mut hasher = Sha256::new();
                hasher.update(bytes.clone());
                let post_sha = hasher.finalize();
                let mut canonical_hdrs =
                    match signed_hdrs.contains("content-type") {
                        true =>
                            match headers.get("Content-Type") {
                                Some(ct) => format!("content-type:{}\n", ct.to_str().unwrap()),
                                _ => return v4_error_ret(&mut error_msg, "content-type found, but not found")
                            },
                        _ =>  {
                            "".to_string()
                        }
                };
                canonical_hdrs.push_str(format!("host:{}\nx-osc-date:{}\n", host, x_date).as_str());

                let canonical_request = format!(
                    "POST
{}

{}
{}
{:x}",
                    uri.path(),
                    canonical_hdrs,
                    signed_hdrs, post_sha);
                println!("{}", canonical_request);
                let credential_scope = format!("{}/{}/{}/{}",
                                               short_date, region, api, "osc4_request");
                println!("==canonical_request ret==\n{}", canonical_request);
                let mut hasher = Sha256::new();
                hasher.update(canonical_request);
                let canonical_request_sha = hasher.finalize();
                let str_to_sign = format!("{}-HMAC-SHA256
{}
{}
{:x}", which_v4, x_date, credential_scope, canonical_request_sha);

                let true_sk = match u["secret_key"].as_str() {
                    Some(v) => v,
                    _ => return v4_error_ret(&mut error_msg, "fail to get secret_key")
                };

                let mut hmac = match HmacSha256::new_from_slice(format!("{}{}", which_v4, true_sk).as_bytes()) {
                    Ok(v) => v,
                    _ => return false
                };
                hmac.update(short_date.as_bytes());
                hmac =  match HmacSha256::new_from_slice(&hmac.finalize().into_bytes()) {
                    Ok(v) => v,
                    _ => return false
                };
                hmac.update(region.as_bytes());

                hmac =  match HmacSha256::new_from_slice(&hmac.finalize().into_bytes()) {
                    Ok(v) => v,
                    _ => return false
                };

                hmac.update(api.as_bytes());

                hmac =  match HmacSha256::new_from_slice(&hmac.finalize().into_bytes()) {
                    Ok(v) => v,
                    _ => return false
                };
                hmac.update(b"osc4_request");

                hmac =  match HmacSha256::new_from_slice(&hmac.finalize().into_bytes()) {
                    Ok(v) => v,
                    _ => return false
                };
                hmac.update(str_to_sign.as_bytes());
                let signature = hmac.finalize();

                format!("{:x}", signature.clone().into_bytes()) == send_signature
            }) {
                Some(idx) => {
                    user_id = idx;
                    auth = AuthType::AkSk
                },
                _ => {
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    *response.body_mut() = Body::from(error_msg);
                    return Ok(response)
                }
            }

        } else if auth != AuthType::None {
            return bad_auth("\"Authorization Header wrong Format\"".to_string());
        }
    } else {
        auth = AuthType::AkSk
    }

    let to_call = match cfg["in_convertion"] == true {
        true => {
            println!("path: {}", uri.path());
            let ret = match uri.path() {
                "/" | "/icu/" | "directlinks" | "fcu" => {

                    let mut in_args = json::JsonValue::new_object();
                    let args_str = std::str::from_utf8(&bytes).unwrap();
                    let mut path = uri.path();

                    let in_json = json::parse(args_str);
                    if (in_json.is_ok() && in_json.unwrap().has_key("Action")) || path.contains("icu") {
                        api = "icu".to_string()
                    }
                    if path.contains("directlinks") {
                        api = "directlinks".to_string()
                    }
                    if path.contains("fcu") {
                        api = "fcu".to_string()
                    }

                    println!("({}): {} ==== {:?}", api, args_str, method);
                    if api == "icu" {
                        let in_json = json::parse(args_str).unwrap();

                        if in_json["Action"] == "ReadConsumptionAccount" {
                            path = "/ReadConsumptionAccount"
                        } else if in_json["Action"] == "ReadPublicCatalog" {
                            path = "/ReadPublicCatalog"
                        } else if in_json["Action"] == "ListAccessKeys" {
                            path = "/ReadAccessKeys"
                        } else if in_json["Action"] == "GetAccount" {
                            path = "/ReadAccounts"
                        } else if in_json["Action"] == "ReadQuotas" {
                            path = "/ReadQuotas"
                        }
                    } else if api == "directlink" {
                        let action = headers.get("x-amz-target").unwrap();
                        println!("{:?}", action);
                        if action == "OvertureService.DescribeConnections" {
                            path = "/ReadDirectLinks"
                        }
                    } else if api != "api" || auth == AuthType::None {
                        let split = args_str.split('&');
                        for s in split {
                            let mut split = s.split('=');
                            let key = split.next().unwrap();
                            let val = split.next();

                            println!("is {} = {:?}", key, val);
                            if key == "Action" {
                                let action = val.unwrap();

                                if action == "CreateKeyPair" {
                                    out_convertion = true;
                                    api = "fcu".to_string();
                                    path = "/CreateKeypair"
                                } else if action == "ReadPublicIpRanges" {
                                    out_convertion = true;
                                    api = "fcu".to_string();
                                    path = "/ReadPublicIpRanges"
                                } else if action == "DescribeRegions" {
                                    out_convertion = true;
                                    api = "fcu".to_string();
                                    path = "/ReadRegions"
                                } else if action == "DescribeImages" {
                                    out_convertion = true;
                                    api = "fcu".to_string();
                                    path = "/ReadImages"
                                } else if action == "DescribeInstances" {
                                    out_convertion = true;
                                    api = "fcu".to_string();
                                    path = "/ReadVms"
                                }
                            } else if key == "KeyName" {
                                in_args["KeypairName"] = val.unwrap().into()
                            }
                        }
                    }
                    bytes = hyper::body::Bytes::from(in_args.dump());
                    RicCall::from_str(path)
                },
                _ => RicCall::from_str(uri.path())
            };
            ret
        },
        _ => RicCall::from_str(uri.path())
    };

    // match (req.method(), req.uri().path())
    println!("{:?}", to_call);
    match to_call {
        Ok(which_call) => {
            let res = try_conver_response(which_call.eval(
                main_json, cfg, bytes, user_id, req_id, headers,
                auth
            ), out_convertion);
            let mut response = Response::new(Body::empty());
            if api == "directlink" {
                response.headers_mut().append("x-amz-requestid", req_id.to_string().parse().unwrap());
            }
            *response.status_mut() = res.1;
            response.headers_mut().append("Content-Type", "application/json".parse().unwrap());
            *response.body_mut() = Body::from(res.0);
            Ok(response)
        },
        _ => {
            let mut response = Response::new(Body::empty());
            println!("Unknow call {}", uri.path());
            *response.status_mut() = StatusCode::NOT_FOUND;
            Ok(response)
        }
    }
}

#[tokio::main]
async fn main() {
    println!("Hello World!");

    let args: Vec<String> = env::args().collect();
    let usr_cfg_path = match args.len()  {
        2 => args[1].clone(),
        _ => format!("{}/.osc/ricochet.json",
                     env::var("HOME").unwrap())
    };
    let mut cfg = match fs::read_to_string(&usr_cfg_path) {
        Ok(users) => json::parse(users.as_str()).unwrap(),
        Err(error) => {
            println!("error opening {}: {}, Defaulting to no auth\n", usr_cfg_path, error);
            json::object!{
                auth_type: "none",
                // user is osef tier, with none, but we need at last one fake for below iteration
                users: [{}]
            }
        }
    };
    if !cfg.has_key("users") {
        cfg["users"] = json::array![{}];
    }
    println!("{:#}", cfg.dump());
    let mut connection = json::JsonValue::new_array();
    for (cnt_users, _m) in cfg["users"].members().enumerate() {
        connection.push(json::object!{
            Vms: json::JsonValue::new_array(),
            FlexibleGpus: json::JsonValue::new_array(),
            LoadBalancers: json::array!{},
            Images: json::array!{
                json::object!{
                    AccountId: format!("{:08x}", 0xffffff),
                    ImageId: format!("ami-{:08x}", 0xffffff00u32),
                    AccountAlias:"Outscale",
                    ImageName: "Fill More is for Penguin General"
                }
            },
            SecurityGroups: json::array!{
                json::object!{
                    Tags: json::array!{},
                    SecurityGroupId: format!("sg-{:08x}", 0xffffff00u32),
                    AccountId: format!("{:08x}", cnt_users),
                    OutboundRules: json::array!{},
                    InboundRules: json::array!{},
                    SecurityGroupName: "default",
                    Description: "default security group",
                }
            },
            DirectLinks: json::JsonValue::new_array(),
            Nics: json::JsonValue::new_array(),
            Nets: json::JsonValue::new_array(),
            Subnets: json::JsonValue::new_array(),
            RouteTables: json::JsonValue::new_array(),
            Volumes: json::JsonValue::new_array(),
            Tags: json::JsonValue::new_array(),
            Keypairs: json::JsonValue::new_array(),
            InternetServices: json::JsonValue::new_array(),
            PublicIps: json::JsonValue::new_array(),
            LinkPublicIps: json::JsonValue::new_array()
        }).unwrap();
    }
    let tls = matches!(cfg["tls"] == true, true);
    let connection = Mutex::new(connection);
    let connection = Arc::new(connection);
    let cfg = Arc::new(Mutex::new(cfg));
    let requet_id = Arc::new(AtomicUsize::new(0));

    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let any_server = match tls {
        true => match hyper_from_pem_files("cert.crt", "cert.key", Protocols::ALL, &addr) {
            Ok(server) => server.serve(
                make_service_fn( move |_| { // first move it into the closure
                    // closure can be called multiple times, so for each call, we must
                    // clone it and move that clone into the async block
                    let connection = connection.clone();
                    let requet_id = requet_id.clone();
                    let cfg = cfg.clone();
                    async move {
                        // async block is only executed once, so just pass it on to the closure
                        Ok::<_, hyper::Error>(service_fn( move |_req| {
                            let connection =  connection.clone();
                            let id = requet_id.fetch_add(1, Ordering::Relaxed);
                            let cfg = cfg.clone();
                            // but this closure may also be called multiple times, so make
                            // a clone for each call, and move the clone into the async block
                            async move { handler(_req, &connection, id, &cfg).await }
                        }))
                    }
                })
            ).await,
            _ => {eprintln!("server failt to create with tls (bad key ?)"); return }
        },
        _ => Server::bind(&addr).serve(
            make_service_fn( move |_| {
                let connection = connection.clone();
                let requet_id = requet_id.clone();
                let cfg = cfg.clone();
                async move {
                    Ok::<_, hyper::Error>(service_fn( move |_req| {
                        let connection =  connection.clone();
                        let id = requet_id.fetch_add(1, Ordering::Relaxed);
                        let cfg = cfg.clone();
                        async move { handler(_req, &connection, id, &cfg).await }
                    }))
                }
            })
        ).await
    };

    if let Err(e) = any_server {
        eprintln!("server error: {}", e);
    }
    // Run this server for... forever!
}
