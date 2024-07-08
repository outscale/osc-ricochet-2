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
use json::JsonValue;
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

fn bad(req_id: usize ,mut json: json::JsonValue,
                error:  &str, num: i32, type_err:  &str) ->
    Result<(String, StatusCode), (String, StatusCode)> {
        eprintln!("bad: {}", error);
        json["Errors"] = json::array![json::object!{Type: type_err, Details: error, Code: num}];
        Err((jsonobj_to_strret(json, req_id), StatusCode::from_u16(400).unwrap()))
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

fn get_default_subregion(cfg: &JsonValue) -> String {
    match cfg.has_key("region") {
        true => match cfg["region"].has_key("subregions") {
            true => format!("{}{}", cfg["region"]["name"], cfg["region"]["subregions"][0]),
            _ => format!("{}a", cfg["region"]["name"])
        },
        _ => "mud-half-3a".into()
    }
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
    CreateNatService,
    CreateSnapshot,
    CreateImageExportTask,
    CreateNic,
    CreateNetPeering,
    CreateVirtualGateway,
    CreateClientGateway,

    DeleteClientGateway,
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
    DeleteNatService,
    DeleteSnapshot,
    DeleteImage,
    DeleteNic,
    DeleteNetPeering,
    DeleteVirtualGateway,

    ReadImageExportTasks,
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
    ReadNatServices,
    ReadSnapshots,
    ReadClientGateways,
    ReadVmTypes,
    ReadNics,
    ReadNetPeerings,
    ReadVirtualGateways,

    LinkInternetService,
    LinkRouteTable,
    LinkVolume,
    LinkPublicIp,
    LinkFlexibleGpu,
    LinkVirtualGateway,

    UnlinkFlexibleGpu,
    UnlinkInternetService,
    UnlinkRouteTable,
    UnlinkVolume,
    UnlinkPublicIp,
    UnlinkVirtualGateway,

    UpdateVm,
    UpdateImage,

    StartVms,
    StopVms,

    AcceptNetPeering,
    RejectNetPeering,

    // Free Calls
    ReadPublicCatalog,
    ReadRegions,
    ReadSubregions,
    ReadPublicIpRanges
}

impl RicCall {
    fn is_free(&self) -> bool {
        matches!(*self, RicCall::ReadPublicCatalog | RicCall::ReadRegions | RicCall::ReadPublicIpRanges | RicCall::ReadVmTypes)
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

        macro_rules! array_remove_3 {
            ($json:expr, $req_id:expr, $array:expr, $predicate:expr, $then:expr) => {{
                match $array.members().position($predicate) {
                    Some(idx) => {$array.array_remove(idx);},
                    None => $then
                }
            }}
        }

        macro_rules! array_remove_2 {
            ($json:expr, $req_id:expr, $array:expr, $predicate:expr) => {
                array_remove_3!($json, $req_id, $array, $predicate,
                return bad_argument($req_id, $json, "Element not found(alerady destroy ?"))
            }
        }

        macro_rules! array_remove {
            ($array:expr, $predicate:expr) => {
                array_remove_2!(json, req_id, $array, $predicate)
            }
        }

        macro_rules! add_security_group {
            ($in_json:expr, $req_id:expr, $resource:expr) => {
                for sg_id in $in_json["SecurityGroupIds"].members() {
                    let name = match main_json[user_id]["SecurityGroups"].members_mut().find(|sg| *sg_id == sg["SecurityGroupId"]) {
                        Some(sg) => &sg["SecurityGroupName"],
                        _ => return bad_argument(req_id, json, format!("can't find SG id {}", sg_id).as_str())
                    };
                    $resource["SecurityGroups"].push(json::object!{
                        "SecurityGroupName": name.clone(),
                        "SecurityGroupId": sg_id.clone()
                    }).unwrap();
                }
                for sg_name in $in_json["SecurityGroups"].members() {
                    let id = match main_json[user_id]["SecurityGroups"].members_mut().find(|sg| *sg_name == sg["SecurityGroupName"]) {
                        Some(sg) => &sg["SecurityGroupId"],
                        _ => return bad_argument(req_id, json, format!("can't find SG named {}", sg_name).as_str())
                    };
                    $resource["SecurityGroups"].push(json::object!{
                        "SecurityGroupName": sg_name.clone(),
                        "SecurityGroupId": id.clone()
                    }).unwrap();
                }
            }
        }

        fn resource_types_to_type(types: &str) -> String {
            match types {
                "Vms" => "vm",
                "SecurityGroups" => "securitygroup",
                "Images" => "image",
                "Volumes" => "volume",
                "FlexibleGpus" => "flexiblegpu",
                "Nets" => "net",
                _ => "unknow"
            }.into()
        }

        fn hosts_of_netmask(netmask: u8) -> u32 {
            2u32.pow((32 - netmask).into())
        }

        macro_rules! used_ips_of_subnet {
            ($subnet_id:expr) => {{
                let mut used_ips = json::array!();
                for nic in main_json[user_id]["Nics"].members() {
                    if nic["SubnetId"] == *($subnet_id) {
                        for pip in nic["PrivateIps"].members() {
                            used_ips.push(pip["PrivateIp"].clone()).unwrap();
                        }
                    }
                }
                used_ips
            }}
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

        macro_rules! check_aksk_auth {
            ($auth:expr) => {{
                if $auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, format!("{:?} requires v4 signature", *self).as_str())
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
                check_aksk_auth!(auth);

                let user_vms = &mut main_json[user_id]["Vms"];
                let mut rm_array = vec![];

                for (idx, vm) in user_vms.members_mut().enumerate() {
                    if vm["State"] == "pending" {
                        vm["State"] = "running".into()
                    } else if vm["State"] == "stopping" {
                        vm["State"] = "stopped".into()
                    } else if vm["State"] == "terminated" {
                        rm_array.push(idx);
                    } else if vm["State"] == "shutting-down" {
                        if vm["VmInitiatedShutdownBehavior"] == "restart" {
                            vm["State"] = "pending".into()
                        } else if vm["VmInitiatedShutdownBehavior"] == "terminated" {
                            vm["State"] = "terminated".into()
                        } else {
                            vm["State"] = "stopping".into()
                        }
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

                                if !filter.is_object() {
                                    return bad_argument(req_id, json, "Filter must be an object")
                                }

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

                for i in rm_array {
                    let vm_id = main_json[user_id]["Vms"][i]["VmId"].clone();
                    for (fgpu_idx, fgpu) in main_json[user_id]["FlexibleGpus"].clone().members().enumerate() {
                        if fgpu["VmId"] == vm_id && fgpu["DeleteOnVmDeletion"] == true  {
                            main_json[user_id]["FlexibleGpus"].array_remove(fgpu_idx);
                        }
                    }
                    main_json[user_id]["Vms"].array_remove(i);
                }
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::StopVms => {
                check_aksk_auth!(auth);
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
                            if vm["VmInitiatedShutdownBehavior"] == "terminated" {
                                new_state = "terminated"
                            } else if vm["VmInitiatedShutdownBehavior"] == "restart" {
                                new_state = "shutting-down"
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
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
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
                                for vm in user_vms.members_mut() {
                                    let mut need_rm = true;

                                    for id in ids.members() {
                                        if *id == vm["VmId"] {
                                            if vm["DeletionProtection"] == true {
                                                return bad(req_id, json, "", 8018,
                                                           "OperationNotSupported");
                                            }
                                            need_rm = true;
                                        }
                                    }
                                    if need_rm {
                                        vm["State"] = "terminated".into();
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
            RicCall::DeleteLoadBalancer  => {
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
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
                            lb["SubregionNames"] = json::array![get_default_subregion(&cfg)];
                        }

                        if in_json.has_key("PublicIp") {
                            match main_json[user_id]["PublicIps"].members().
                                find(|ip| in_json["PublicIp"] == ip["PublicIp"]) {
                                    Some(_) => {},
                                    _ => return bad_argument(
                                        req_id, json, "PublicIp doesn't corespond to an existing Ip")
                                }

                            lb["PublicIp"] = in_json["PublicIp"].clone();
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
	    RicCall::UpdateImage => {
                check_aksk_auth!(auth);
		let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());
                let image_id = require_arg!(in_json, "ImageId");
		let image = match get_by_id!("Images", "ImageId", image_id) {
                    Ok((_, idx)) => &mut main_json[user_id]["Images"][idx],
                    _ => return bad_argument(req_id, json, "Image not found")
                };

		if in_json.has_key("PermissionsToLaunch") {
		    let ptl = &in_json["PermissionsToLaunch"];
		    if  ptl.has_key("Additions") {
			let addition = &ptl["Additions"];

                        if addition["GlobalPermission"] == true {
                            image["PermissionsToLaunch"]["GlobalPermission"] = true.into();
                        }
                        if addition.has_key("AccountIds") {
                            for aid in addition["AccountIds"].members() {
                                match image["PermissionsToLaunch"]["AccountIds"].members().
                                    find(|id| aid == *id) {
                                        Some(_) => {},
                                        _ => image["PermissionsToLaunch"]["AccountIds"].push(aid.clone()).unwrap()
                                }
                            }
                        }
		    }

                    if ptl.has_key("Removals") {
                        let removal = &ptl["Removals"];

                        if removal["GlobalPermission"] == false {
                            image["PermissionsToLaunch"]["GlobalPermission"] = false.into();
                        }
                        if removal.has_key("AccountIds") {
                            for aid in removal["AccountIds"].members() {
                                if let Some((idx, _)) = image["PermissionsToLaunch"]["AccountIds"].members().enumerate().
                                                                    find(|(_, id)| aid == *id) {
                                    image["PermissionsToLaunch"]["AccountIds"].array_remove(idx);
                                }
                            }
                        }
                    }
                }


                println!("{:#}", image.dump());
		json["Image"] = image.clone();
		Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
	    },
	    RicCall::DeleteImage => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
		println!("{:#}", in_json.dump());
                let user_imgs = &mut main_json[user_id]["Images"];
		let id = require_arg!(in_json, "ImageId");
		array_remove!(user_imgs, |n| n["ImageId"] == id &&
		    n["AccountId"] == format!("{:012x}", user_id)
		);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
	    },
            RicCall::ReadImageExportTasks => {
                check_aksk_auth!(auth);

                let user_iets = &mut main_json[user_id]["ImageExportTasks"];

                for iet in user_iets.members_mut() {
                    let mut progress: u32 = iet["Progress"].as_u32().unwrap() + 10;
                    if iet["State"] == "pending/queued" {
                        iet["State"] = "pending".into();
                    }
                    if progress > 100 {
                        progress = 100;
                        if iet["State"] == "pending" {
                            iet["State"] = "completed".into();
                        }
                    }
                    iet["Progress"] = progress.into();
                }

                if !bytes.is_empty() {
                    let in_json = require_in_json!(bytes);
                    let filter = &in_json["Filters"];

                    json["ImageExportTasks"] = json::JsonValue::new_array();

                    for snap in user_iets.members() {
                        let mut need_add = true;

                        need_add = have_request_filter(filter, snap,
                                                       "TaskIds",
                                                       "TaskId", need_add);
                        if need_add {
                            json["ImageExportTasks"].push((*snap).clone()).unwrap();
                        }
                    }

                } else {
                    json["ImageExportTasks"] = (*user_iets).clone();
                }

                println!("{:#}", json.dump());


                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateImageExportTask => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());
                let img_id = require_arg!(in_json, "ImageId");
                match main_json[user_id]["Images"].members().find(|img| img["ImageId"] == img_id) {
                    Some(_) => {}
                    _ => return bad_argument(req_id, json, "iprange size is nope")
                };

                // {"ImageId":"ami-00000001","OsuExport":{"DiskImageFormat":"qcow2","OsuBucket":"test-image-name-9159339220693928153","OsuManifestUrl":"","OsuPrefix":""}}
                let osu_export = require_arg!(in_json, "OsuExport");
                let iet = json::object!{
                    "Tags": [],
                    "ImageId": img_id.clone(),
                    "TaskId": format!("image-export-{:08x}", req_id),
                    "Comment": format!("Export of image {}", img_id),
                    "OsuExport": {
                        "OsuPrefix": optional_arg!(osu_export, "OsuPrefix", ""),
                        "OsuBucket": require_arg!(osu_export, "OsuBucket"),
                        "DiskImageFormat": require_arg!(osu_export, "DiskImageFormat"),
                    },
                    State: "pending/queued",
                    Progress: 0
                };
                main_json[user_id]["ImageExportTasks"].push(iet.clone()).unwrap();
                json["ImageExportTask"] = iet;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateImage => {
                check_aksk_auth!(auth);
                let image_id = format!("ami-{:08x}", req_id);
                let mut image = json::object!{
                    AccountId: format!("{:012x}", user_id),
		    PermissionsToLaunch: {
			GlobalPermission: false,
			AccountIds: []
		    },
                    ImageId: image_id,
		    "StateComment": {},
		    State: "pending",
		    "RootDeviceType": "bsu",
		    "RootDeviceName": "/dev/sda1",
		    "ProductCodes": [
			"0001"
		    ],
		    "Tags": [],
		    Description: "",
		    "BlockDeviceMappings": [
			{
			    "DeviceName": "/dev/sda1",
			    "Bsu": {
				"VolumeType": "standard",
				"DeleteOnVmDeletion": true,
				"VolumeSize": 50,
				"SnapshotId": "snap-12345678"
			    }
			}
		    ],
		    "Architecture": "x86_64",
		    "FileLocation": "123456789012/create-image-example",
		    "ImageType": "machine",
		    "CreationDate": "2010-10-01T12:34:56.789Z",
		    ImageName: "an-image-with-no-name",
                };
                if !users[user_id]["login"].is_null() {
                    image["AccountAlias"] = users[user_id]["login"].clone()
                } else {
		    image["AccountAlias"] = "unknow".into()
 		}

                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Ok(in_json) => {
			    println!("{:#}", in_json.dump());
                            if in_json.has_key("ImageName") {
                                image["ImageName"] = in_json["ImageName"].clone();
                            }
                            if in_json.has_key("Description") {
                                image["Description"] = in_json["Description"].clone();
                            }
                        },
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalide json");
                        }
                    }
                }
                main_json[user_id]["Images"].push(
                    image.clone()).unwrap();
                json["Image"] = image;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateSubnet => {
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let user_nets = &mut main_json[user_id]["RouteTables"];
                // TODO: check subnet is destroyable
                let id = require_arg!(in_json, "RouteTableId");
                array_remove!(user_nets, |n| n["RouteTableId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteSubnet => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let user_nets = &mut main_json[user_id]["Subnets"];
                // TODO: check subnet is destroyable
                let id = require_arg!(in_json, "SubnetId");
                array_remove!(user_nets, |n| n["SubnetId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateNet => {
                check_aksk_auth!(auth);
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
                        _ => return bad_argument(req_id, json, "you range is pure &@*$ i mean invalid")
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
                check_aksk_auth!(auth);
                // TODO
                json["ricochet-info"] = "CALL LOGIC NOT YET IMPLEMENTED".into();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadNatServices => {
                check_aksk_auth!(auth);

                let user_dl = &main_json[user_id]["NatServices"];

                json["NatServices"] = (*user_dl).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))

            },
            RicCall::DeleteNatService => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let user_ns = &mut main_json[user_id]["NatServices"];
                let id = require_arg!(in_json, "NatServiceId");

                array_remove!(user_ns, |n| n["NatServiceId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))

            },
            RicCall::CreateNatService => {
                check_aksk_auth!(auth);
                let user = &mut main_json[user_id];
                let in_json = require_in_json!(bytes);
                let ip_id = require_arg!(in_json, "PublicIpId");
                let subnet_id = require_arg!(in_json, "SubnetId");
                let ip = match user["PublicIps"].members().find(|ip| ip_id == ip["PublicIpId"]) {
                    Some(ip) => ip,
                    _ => return bad_argument(req_id, json, "CreateNatService doesn't corespond to an existing id")
                };
                let nat_service = json::object!{
                    SubnetId: subnet_id,
                    State: "available",
                    PublicIps: [
                        {
                            PublicIpId: ip_id.clone(),
                            PublicIp: ip["PublicIp"].clone()
                        }
                    ],
                    NatServiceId: format!("nat-{:08x}", req_id)
                };

                main_json[user_id]["NatServices"].push(
                    nat_service.clone()).unwrap();
                json["NatService"] = nat_service;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadSnapshots => {
                check_aksk_auth!(auth);
                let snapshots = &mut main_json[user_id]["Snapshots"];
                for snap in snapshots.members_mut() {
                    if snap["State"] == "pending" {
                        snap["State"] = "completed".into();
                        snap["Progress"] = 100.into();
                    }
                }

                if !bytes.is_empty() {
                    let in_json = require_in_json!(bytes);
                    let filter = &in_json["Filters"];

                    json["Snapshots"] = json::JsonValue::new_array();

                    for snap in snapshots.members() {
                        let mut need_add = true;

                        need_add = have_request_filter(filter, snap,
                                                       "SnapshotIds",
                                                       "SnapshotId", need_add);
                        if need_add {
                            json["Snapshots"].push((*snap).clone()).unwrap();
                        }
                    }

                } else {
                    json["Snapshots"] = (*snapshots).clone();
                }
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteSnapshot => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let snapshots = &mut main_json[user_id]["Snapshots"];
                let id = require_arg!(in_json, "SnapshotId");

                array_remove!(snapshots, |n| n["SnapshotId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateSnapshot => {
                check_aksk_auth!(auth);

                let in_json = require_in_json!(bytes);
                let snap = if in_json.has_key("VolumeId") {
                    let volume_id = in_json["VolumeId"].clone();

                    match get_by_id!("Volumes", "VolumeId", volume_id) {
                        Ok((t, idx)) => json::object!{
                            VolumeSize: main_json[user_id][t][idx]["Size"].clone(),
                            AccountId: format!("{:12x}", user_id),
                            VolumeId: volume_id,
                            CreationDate: main_json[user_id][t][idx]["CreationDate"].clone(),
                            "PermissionsToCreateVolume": {
                                "GlobalPermission": false,
                                "AccountIds": []
                            },
                            Progress: 0,
                            SnapshotId: format!("snap-{:08x}", req_id),
                            State: "pending",
                            Description: optional_arg!(in_json, "Description", "Snapshot created from a volume"),
                            Tags: []

                        },
                        _ => return bad_argument(req_id, json, format!("Volume {} not found", volume_id).as_str())
                    }
                } else if in_json.has_key("SourceSnapshotId") {
                    let snap_id = in_json["SourceSnapshotId"].clone();

                    match get_by_id!("Snapshots", "SnapshotId", snap_id) {
                        Ok((t, idx)) => json::object!{
                            VolumeSize: main_json[user_id][t][idx]["VolumeSize"].clone(),
                            AccountId: format!("{:012x}", user_id),
                            CreationDate: main_json[user_id][t][idx]["CreationDate"].clone(),
                            "PermissionsToCreateVolume": {
                                "GlobalPermission": false,
                                "AccountIds": []
                            },
                            Progress: 100,
                            SnapshotId: format!("snap-{:08x}", req_id),
                            State: "completed",
                            Description: optional_arg!(in_json, "Description", "Snapshot copied from another snapshot"),
                            Tags: []
                        },
                        _ => return bad_argument(req_id, json,
                                                 format!("Snapshot {} not found", snap_id).as_str())
                    }

                } else {
                    return bad_argument(req_id, json, "CreateSnapshot require either VolumeId or SourceSnapshotId");
                };
                main_json[user_id]["Snapshots"].push(snap.clone()).unwrap();
                json["Snapshot"] = snap;
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateRoute => {
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let route_table_id = require_arg!(in_json, "RouteTableId");
                let subnet_id = require_arg!(in_json, "SubnetId");

                let subnet_net_id = match get_by_id!("Subnets", "SubnetId", subnet_id) {
                    Ok((_, idx)) => main_json[user_id]["Subnets"][idx]["NetId"].clone(),
                    _ => return bad_argument(req_id, json, "Subnet not found")
                };
                let route_table = match get_by_id!("RouteTables", "RouteTableId", route_table_id) {
                    Ok((_, idx)) => &mut main_json[user_id]["RouteTables"][idx],
                    _ => return bad_argument(req_id, json, "Route Table not found")
                };
                if subnet_net_id != route_table["NetId"] {
                    return bad_argument(req_id, json, "The Subnet and the route table must be in the same Net.")
                }
                let link_route_table = json::object!{
                    Main: route_table["LinkRouteTables"].is_empty(),
                    LinkRouteTableId: format!("rtbassoc-{:08x}", req_id),
                    RouteTableId: route_table["RouteTableId"].clone(),
                    NetId: subnet_net_id.clone()
                };

                route_table["LinkRouteTables"].push(link_route_table.clone()).unwrap();
                json["LinkRouteTableId"] = link_route_table["LinkRouteTableId"].clone();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::UnlinkRouteTable => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let link_route_table_id = require_arg!(in_json, "LinkRouteTableId");

                let get_rt_link_idx = || -> Option<(usize, usize)> {
                    for (route_table_idx, route_table) in main_json[user_id]["RouteTables"].members().enumerate() {
                        if let Some(link_route_table_idx) = route_table["LinkRouteTables"].members().position(|link| link["LinkRouteTableId"] == link_route_table_id) {
                            return Some((route_table_idx, link_route_table_idx));
                        }
                    }
                    None
                };
                let (route_table_idx, link_route_table_idx) = match get_rt_link_idx() {
                    Some((rt_idx, lrt_idx)) => (rt_idx, lrt_idx),
                    None => return bad_argument(req_id, json, format!("can't find the link route table {}", link_route_table_id).as_str())
                };

                main_json[user_id]["RouteTables"][route_table_idx]["LinkRouteTables"].array_remove(link_route_table_idx);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },

	    RicCall::ReadVmTypes => {
		json["VmTypes"] = json::array![json::object!{
		    "VolumeCount": 0,
		    "VmTypeName": "t2.small",
		    "BsuOptimized": false,
		    "MaxPrivateIps": 4,
		    "MemorySize": 2,
		    "VcoreCount": 1
		}];
		Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
	    },

            RicCall::CreateClientGateway => {
                check_aksk_auth!(auth);

                let in_json = require_in_json!(bytes);
                let cg = json::object!{
                    "State": "available",
                    BgpAsn: require_arg!(in_json, "BgpAsn"),
                    "Tags": [],
                    ClientGatewayId: format!("cwg-{:08x}", req_id),
                    ConnectionType: require_arg!(in_json, "ConnectionType"),
                    PublicIp: require_arg!(in_json, "PublicIp")
                };

                main_json[user_id]["ClientGateways"].push(
                    cg.clone()).unwrap();
                json["ClientGateway"] = cg;

		Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },

            RicCall::DeleteClientGateway => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let user_cgs = &mut main_json[user_id]["ClientGateways"];
                let id = require_arg!(in_json, "ClientGatewayId");

                for cg in user_cgs.members_mut() {
                    if cg["ClientGatewayId"] == id {
                        cg["State"] = "deleting".into();
                    }
                }
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            }
	    RicCall::ReadClientGateways => {
                check_aksk_auth!(auth);

                let old_cgs = main_json[user_id]["ClientGateways"].clone();
                let user_cgs = &mut main_json[user_id]["ClientGateways"];
                array_remove_3!(in_json, req_id, user_cgs, |n| n["State"] == "deleted", {});
                for cg in user_cgs.members_mut() {
                    if cg["State"] == "deleting" {
                        cg["State"] = "deleted".into();
                    }
                }

                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Ok(in_json) => {
                            println!("{:#}", in_json.dump());
                            if in_json.has_key("Filters") {
                                let filter = &in_json["Filters"];
                                json["ClientGateways"] = json::JsonValue::new_array();

                                if !filter.is_object() {
                                    return bad_argument(req_id, json, "Filter must be an object")
                                }
                                for cg in old_cgs.members() {
                                    let mut need_add = true;

                                    need_add = have_request_filter(filter, cg,
                                                                   "ClientGatewayIds", "ClientGatewayId", need_add);
                                    if need_add {
                                        json["ClientGateways"].push((*cg).clone()).unwrap();
                                    }
                                }


                            } else {
                                json["ClientGateways"] = old_cgs;
                            }
                        },
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalide json");
                        }
                    }
                } else {
                    json["ClientGateways"] = old_cgs;
                }
		Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
	    },
            RicCall::LinkInternetService => {
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);

                println!("{:#}", in_json.dump());

                let ip = format!("eipassoc-{:08x}", req_id);
                let ip_id = if in_json.has_key("PublicIp") {
                    let pub_ip = in_json["PublicIp"].clone();

                    match main_json[user_id]["PublicIps"].members().
                        find(|ip| pub_ip == ip["PublicIp"]) {
                            Some(ip) => ip["PublicIpId"].clone(),
                            _ => return bad_argument(
                                req_id, json, "PublicIp doesn't corespond to an existing Ip")
                    }
                } else if in_json.has_key("PublicIpId") {
                    in_json["PublicIpId"].clone()
                } else {
                    return bad_argument(req_id, json, "require either PublicIpId or PublicIp")
                };
                let user = &mut main_json[user_id];
                let ip_idx = match user["PublicIps"].members().position(|iwg| ip_id == iwg["PublicIpId"]) {
                    Some(idx) => idx,
                    _ => return bad_argument(req_id, json, "SecurityGroupId doesn't corespond to an existing id")
                };
                let mut to_push = json::object!{
                    LinkPublicIpId: ip.clone(),
                    PublicIpId: ip_id
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
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());
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
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let user_iwgs = &mut main_json[user_id]["InternetServices"];
                // TODO: check net is destroyable
                let id = require_arg!(in_json, "InternetServiceId");
                array_remove!(user_iwgs, |n| n["InternetServiceId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeletePublicIp => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());
                let user_iwgs = &mut main_json[user_id]["PublicIps"];
                // TODO: check net is destroyable
                let id = require_arg!(in_json, "PublicIpId");
                array_remove!(user_iwgs, |n| n["PublicIpId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteNet => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let user_nets = &mut main_json[user_id]["Nets"];
                // TODO: check net is destroyable
                let id = require_arg!(in_json, "NetId");
                array_remove!(user_nets, |n| n["NetId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadKeypairs => {
                check_aksk_auth!(auth);

                let user_kps = &main_json[user_id]["Keypairs"];

                let mut kps = (*user_kps).clone();

                for k in kps.members_mut() {
                    k.remove("PrivateKey");
                }
                json["Keypairs"] = kps;

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadNets => {
                check_aksk_auth!(auth);

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

                let region_name = match cfg.has_key("region") {
                    true => cfg["region"]["name"].as_str().unwrap(),
                    _ => "mud-half-3"
                };

                json["Regions"] = json::array![
                    json::object!{
                        Endpoint: "127.0.0.1:3000",
                        RegionName: region_name
                    }
                ];

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadSubregions  => {
                check_aksk_auth!(auth);
                json["Subregions"] = json::array![];
                match cfg.has_key("region") {
                    true => {
                        let region = & cfg["region"];
                        let region_name = region["name"].as_str().unwrap();
                        match region.has_key("subregions") {
                            true => {
                                for sub in region["subregions"].members() {
                                    json["Subregions"].push(json::object!{
                                        State: "available",
                                        RegionName: region_name,
                                        SubregionName: format!("{}{}", region_name, sub),
                                        LocationCode: "PAR1"
                                    }).unwrap();
                                }
                            },
                            _ => {
                                json["Subregions"].push(json::object!{
                                    State: "available",
                                    RegionName: region_name,
                                    SubregionName: format!("{}a", region_name),
                                    LocationCode: "PAR1"
                                }).unwrap();
                                json["Subregions"].push(json::object!{
                                    State: "available",
                                    RegionName: region_name,
                                    SubregionName: format!("{}b", region_name),
                                    LocationCode: "PAR1"
                                }).unwrap();

                            }
                        }
                    },
                    _ => {
                        json["Subregions"].push(json::object!{
                            State: "available",
                            RegionName: "mud-half-3",
                            SubregionName: "mud-half-3a",
                            LocationCode: "PAR1"
                        }).unwrap();
                        json["Subregions"].push(json::object!{
                            State: "available",
                            RegionName: "mud-half-3",
                            SubregionName: "mud-half-3b",
                            LocationCode: "PAR1"
                        }).unwrap();
                    }
                };

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadAccounts  => {
                check_aksk_auth!(auth);
                let email = users[user_id]["login"].clone();

                json["Accounts"] =
                    json::array![
                        json::object!{
                            City:"カカリコ",
                            CompanyName: "plouf",
                            Country: "ハイラル",
                            CustomerId: format!("{:012x}", user_id),
                            Email: match email.is_null() {
                                true => "RICOCHET_UNKNOW.com",
                                _ => email.as_str().unwrap()
                            },
                            FirstName: "oui",
                            JobTitle: "oui",
                            LastName: "non",
                            MobileNumber: "+336 01 02 03 04",
                            PhoneNumber: "011 8 999 881 99 911 9 725 3",
                            StateProvince: "ok",
                            VatNumber: "009",
                            ZipCode: "5"
                    }];

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadImages  => {
                check_aksk_auth!(auth);
                if auth != AuthType::AkSk {
                    return eval_bad_auth(req_id, json, "ReadImages require v4 signature")
                }

                let user_imgs = &mut main_json[user_id]["Images"];
                for img in user_imgs.members_mut() {
                    if img["State"] == "pending" {
                        img["State"] = "available".into();
                    }
                }

                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalid JSON format")
                        },
                        Ok(in_json) => {
                            println!("{:#}", in_json.dump());

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
                                                                   "ImageIds",
                                                                   "ImageId", need_add);

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
                check_aksk_auth!(auth);

                let user_sgs = &main_json[user_id]["SecurityGroups"];
                if !bytes.is_empty() {
                    let in_json = require_in_json!(bytes);
                    println!("ReadSGm in: {:#}", in_json.dump());
                    if in_json.has_key("Filters") {
                        let filters = &in_json["Filters"];
                        json["SecurityGroups"] = json::JsonValue::new_array();
                        for sg in user_sgs.members() {
                            let mut need_add = true;

                            need_add = have_request_filter(filters, sg,
                                                           "SecurityGroupNames",
                                                           "SecurityGroupName", need_add);
                            need_add = have_request_filter(filters, sg,
                                                           "SecurityGroupIds",
                                                           "SecurityGroupId", need_add);
                            if need_add {
                                json["SecurityGroups"].push((*sg).clone()).unwrap();
                            }
                        }
                    } else {
                        json["SecurityGroups"] = (*user_sgs).clone();
                    }
                } else {
                    json["SecurityGroups"] = (*user_sgs).clone();
                }

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadDirectLinks  => {
                check_aksk_auth!(auth);

                let user_dl = &main_json[user_id]["DirectLinks"];

                json["DirectLinks"] = (*user_dl).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::LinkVolume => {
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let user_nets = &mut main_json[user_id]["Volumes"];
                let id = require_arg!(in_json, "VolumeId");

                array_remove!(user_nets, |n| n["VolumeId"] == id);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::UnlinkVolume => {
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);

                let user_rts = &main_json[user_id]["RouteTables"];

                json["RouteTables"] = (*user_rts).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadSubnets  => {
                check_aksk_auth!(auth);

                let user_rts = &main_json[user_id]["Subnets"];

                json["Subnets"] = (*user_rts).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadInternetServices  => {
                check_aksk_auth!(auth);

                let user_imgs = &main_json[user_id]["InternetServices"];

                json["InternetServices"] = (*user_imgs).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadPublicIps  => {
                check_aksk_auth!(auth);

                let user_imgs = &main_json[user_id]["PublicIps"];

                if !bytes.is_empty() {
                    let in_json = require_in_json!(bytes);
                    let filter = &in_json["Filters"];
                    let public_ips = &mut main_json[user_id]["PublicIps"];

                    json["PublicIps"] = json::JsonValue::new_array();

                    for snap in public_ips.members() {
                        let mut need_add = true;

                        need_add = have_request_filter(filter, snap,
                                                       "PublicIpIds",
                                                       "PublicIpId", need_add);
                        if need_add {
                            json["PublicIps"].push((*snap).clone()).unwrap();
                        }
                    }

                } else {
                    json["PublicIps"] = (*user_imgs).clone();
                }

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadLinkPublicIps  => {
                check_aksk_auth!(auth);

                let user_imgs = &main_json[user_id]["LinkPublicIps"];

                json["LinkPublicIps"] = (*user_imgs).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadTags  => {
                check_aksk_auth!(auth);

                let user_tags = &main_json[user_id]["Tags"];

                if !bytes.is_empty() {
                    let in_json = require_in_json!(bytes);

                    if in_json.has_key("Filters") {
                        let filters = &in_json["Filters"];
                        json["Tags"] = json::JsonValue::new_array();

                        for t in user_tags.members() {
                            let mut need_add = true;

                            need_add = have_request_filter(filters, t,
                                                           "ResourceIds",
                                                           "ResourceId", need_add);

                            if need_add {
                                json["Tags"].push((*t).clone()).unwrap();
                            }
                        }
                    }

                } else {
                    json["Tags"] = (*user_tags).clone();
                }

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadVolumes  => {
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);

                let user_vms = &main_json[user_id]["LoadBalancers"];

                json["LoadBalancers"] = (*user_vms).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadConsumptionAccount  => {
                check_aksk_auth!(auth);
                println!("RicCall::ReadConsumptionAccount !!!");
                Ok((jsonobj_to_strret(json::object!{
                    ConsumptionEntries:
                    json::array!{
                        json::object!{
                            AccountId: format!("{:012x}", user_id),
                            Value: 0
                        }
                    }
                }, req_id), StatusCode::OK))
            },
            RicCall::ReadFlexibleGpus  => {
                check_aksk_auth!(auth);

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
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);

                let in_json = require_in_json!(bytes);
                println!("DeleteSecurityGroup: {:#}", in_json.dump());
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
                check_aksk_auth!(auth);

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
                check_aksk_auth!(auth);

                let in_json = require_in_json!(bytes);

                let dl = json::object!{
                    AccountId: format!("{:012x}", user_id),
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
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);
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
                check_aksk_auth!(auth);

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
                check_aksk_auth!(auth);
                let sg_id = format!("sg-{:08x}", req_id);
                let in_json = require_in_json!(bytes);
                let mut sg = json::object!{
                    Tags: json::array!{},
                    SecurityGroupId: sg_id,
                    AccountId: format!("{:012x}", user_id),
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
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                let vm_id = require_arg!(in_json, "VmId");
                json["VmId"] = vm_id;
                json["AdminPassword"] = "w0l0l0".into();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::UpdateVm => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());
                let vm_id = require_arg!(in_json, "VmId");
                json["ricochet-info"] = format!("vm id: {}, but update vm barly implemented", vm_id).into();
                let vm = match get_by_id!("Vms", "VmId", vm_id) {
                    Ok((_, idx)) => &mut main_json[user_id]["Vms"][idx],
                    _ => return bad_argument(req_id, json, "Vm not found")
                };
                if in_json.has_key("VmInitiatedShutdownBehavior") {
                    vm["VmInitiatedShutdownBehavior"] = in_json["VmInitiatedShutdownBehavior"].clone()
                }
                if in_json.has_key("KeypairName") {
                    vm["KeypairName"] = in_json["KeypairName"].clone()
                }
                if in_json.has_key("DeletionProtection") {
                    vm["DeletionProtection"] = in_json["DeletionProtection"].clone()
                }

		json["Vm"] = vm.clone();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateVms => {
                check_aksk_auth!(auth);
                let vm_id = format!("i-{:08x}", req_id);
                let in_json = match json::parse(std::str::from_utf8(&bytes).unwrap()) {
                    Ok(in_json) => in_json,
                    Err(_) => {
                        json::object!{}
                    }
                };

                // {"BootOnCreation":true,"DeletionProtection":false,"ImageId":"ami-cd8d714e","KeypairName":"deployer","MaxVmsCount":1,"MinVmsCount":1,"NestedVirtualization":false,"SecurityGroupIds":["sg-ffffff00"],"SubnetId":"subnet-00000008","VmType":"tinav4.c1r1p2"}
                println!("{:#}", in_json.dump());

                // Vreate Volumes, should be optional TODO
                let mut vol = json::array![
                    json::object!{
                        VolumeId: format!("vol-{:08x}", req_id),
                        Tags: [],
                        VolumeType: "standard",
                        SubregionName: get_default_subregion(&cfg),
                        State: "creating",
                        CreationDate: "2022-08-01T13:37:54.356Z",
                        Iops: 100,
                        LinkedVolumes: [],
                        Size: 10
                }];

                let mut vm = json::object!{
                    VmType: optional_arg!(in_json, "VmType", "t2.small"),
                    VmInitiatedShutdownBehavior: optional_arg!(in_json, "VmInitiatedShutdownBehavior", "stop"),
                    "State": "running",
                    "StateReason": "",
                    "RootDeviceType": "ebs",
                    "RootDeviceName": "/dev/sda1",
                    "IsSourceDestChecked": true,
                    KeypairName: optional_arg!(in_json, "KeypairName", "my_craft"),
                    "PublicIp": "100.200.60.100",
                    ImageId: optional_arg!(in_json, "ImageId", "ami-00000000"),
                    "PublicDnsName": "ows-148-253-69-185.eu-west-2.compute.outscale.com",
                    DeletionProtection: optional_arg!(in_json, "DeletionProtection", false),
                    "Architecture": "x86_64",
                    "NestedVirtualization": false,
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/sda1",
                            "Bsu": {
                                "VolumeId": vol[0]["VolumeId"].clone(),
                                "State": "attached",
                                "LinkDate": "2022-08-01T13:37:54.356Z",
                                "DeleteOnVmDeletion": true
                            }
                        }
                    ],
                    VmId: vm_id,
                    Placement: {
                        Tenancy: "default",
                        SubregionName: get_default_subregion(&cfg),
                    },
                    "ReservationId": "r-a3df6a95",
                    "Hypervisor": "xen",
                    "ProductCodes": [
                        "0001"
                    ],
                    "CreationDate": "2022-08-01T13:37:54.356Z",
                    "UserData": "",
                    "PrivateIp": "10.0.00.0",
                    "SecurityGroups": [],
                    "BsuOptimized": false,
                    "LaunchNumber": 0,
                    "Performance": "high",
                    "Tags": [],
                    "PrivateDnsName": "ip-10-8-41-9.eu-west-2.compute.internal"
                };

                if in_json.has_key("BlockDeviceMappings") {
                    let mut blockdevicemappings = json::array![];
                    let in_blockdevicemappings = &in_json["BlockDeviceMappings"];
                    vol = json::array![];

                    for in_block in in_blockdevicemappings.members() {
                        let mut out_block = in_block.clone();
                        let out_bsu = &mut out_block["Bsu"];
                        let mut rng = thread_rng();
                        let vol_id: u32 = rng.gen();
                        let v =json::object!{
                            VolumeId: format!("vol-{:08x}", vol_id),
                            Tags: [],
                            VolumeType: optional_arg!(in_block["Bsu"], "VolumeType", "standard"),
                            SubregionName: get_default_subregion(&cfg),
                            State: "creating",
                            CreationDate: "2022-08-01T13:37:54.356Z",
                            Iops: 100,
                            LinkedVolumes: [],
                            Size: in_block["Bsu"]["VolumeSize"].clone()
                        };
                        out_bsu["VolumeId"] = v["VolumeId"].clone();
                        vol.push(v).unwrap();
                        blockdevicemappings.push(out_block).unwrap();
                    }
                    vm["BlockDeviceMappings"] = blockdevicemappings;
                }
                // "Placement":{"SubregionName":"eu-west-2a"}
                if in_json.has_key("Placement") {
                    let in_placement = &in_json["Placement"];

                    if in_placement.has_key("SubregionName") {
                        vm["Placement"]["SubregionName"] = in_placement["SubregionName"].clone();
                    }
                    if in_placement.has_key("Tenancy") {
                        vm["Placement"]["Tenancy"] = in_placement["Tenancy"].clone();
                    }
                }
                if in_json.has_key("SecurityGroupIds") || in_json.has_key("SecurityGroups") {
                    add_security_group!(in_json, req_id, vm);
                } else {
                    vm["SecurityGroups"] = json::array![
                        json::object!{
                            "SecurityGroupName": "default",
                            "SecurityGroupId": format!("sg-{:08x}", 0xffffff00u32)
                        }
                    ];
                }
                main_json[user_id]["Vms"].push(
                    vm.clone()).unwrap();
                for v in vol.members() {
                    main_json[user_id]["Volumes"].push(
                        v.clone()).unwrap();
                }
                json["Vms"] = json::array!{vm};
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateTags|RicCall::DeleteTags => {
                check_aksk_auth!(auth);
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
                        Some(id) => match id.rsplit_once('-') {
                            Some((t, _)) => match t {
                                "sg" => get_by_id!("SecurityGroups", "SecurityGroupId", id),
                                "i" => get_by_id!("Vms", "VmId", id),
                                "ami" => get_by_id!("Images", "ImageId", id),
                                "vol" => get_by_id!("Volumes", "VolumeId", id),
                                "fgpu" => get_by_id!("FlexibleGpus", "FlexibleGpuId", id),
                                "vpc" => get_by_id!("Nets", "NetId", id),
                                "cwg" => get_by_id!("ClientGateways", "ClientGatewayId", id),
                                "image-export" => get_by_id!("ImageExportTasks", "TaskId", id),
                                _ => Err(bad_argument(req_id, json.clone(),
                                                      format!("invalide resource id {}", t).as_str()))
                            },
                            _ => Err(bad_argument(req_id, json.clone(), format!("invalide resource id {}", id).as_str()))
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
                        ntag["ResourceType"] = resource_types_to_type(resource_t).into();

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
                check_aksk_auth!(auth);
                json["QuotaTypes"] = json::array![
                    json::object!{
                        Quotas: json::array![
                            json::object!{
                                ShortDescription: "VM Limit",
                                QuotaCollection: "Compute",
                                AccountId: format!("{:012x}", user_id),
                                Description: "Maximum number of VM this user can own",
                                MaxValue: "not implemented",
                                UsedValue: "not implemented",
                                Name: "bypass_group_size_limit"
                            },
                            json::object!{
                                ShortDescription: "Bypass Group Size Limit",
                                QuotaCollection: "Other",
                                AccountId: format!("{:012x}", user_id),
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
                check_aksk_auth!(auth);
                let user_fgpu = &mut main_json[user_id]["FlexibleGpus"];
                let in_json = require_in_json!(bytes);
                let id = require_arg!(in_json, "FlexibleGpuId");

                array_remove!(user_fgpu, |fgpu| id == fgpu["FlexibleGpuId"]);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteDirectLink => {
                check_aksk_auth!(auth);
                let user_fgpu = &mut main_json[user_id]["DirectLinks"];
                let in_json = require_in_json!(bytes);
                let id = require_arg!(in_json, "DirectLinkId");

                array_remove!(user_fgpu, |fgpu| id == fgpu["DirectLinkId"]);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateFlexibleGpu => {
                check_aksk_auth!(auth);
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
            },
            RicCall::CreateNic => {
                check_aksk_auth!(auth);
                let nic_id = format!("eni-{:08x}", req_id);
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());

                let subnet_id = require_arg!(in_json, "SubnetId");
                let subnet = match main_json[user_id]["Subnets"].members_mut().find(|subnet| subnet_id == subnet["SubnetId"]) {
                    Some(snet) => snet,
                    _ => return bad_argument(req_id, json, format!("can't find subnet id {}", subnet_id).as_str())
                };

                let mut nic = json::object!{
                    SubregionName: get_default_subregion(&cfg),
                    SubnetId: subnet_id.clone(),
                    "State": "available",
                    "IsSourceDestChecked": true,
                    "PrivateDnsName": "",
                    "Tags": [],
                    Description: optional_arg!(in_json, "Description", ""),
                    AccountId: format!("{:012x}", user_id),
                    SecurityGroups: [],
                    "MacAddress": "A1:B2:C3:D4:E5:F6",
                    "NetId": "",
                    NicId: nic_id,
                    PrivateIps: []
                };

                let subnet_st: Ipv4Net = subnet["IpRange"].as_str().unwrap().parse().unwrap();
                let mut used_ips = used_ips_of_subnet!(&subnet_id);
                let mut has_primary_in_req = false;
                if in_json.has_key("PrivateIps") {
                    let mut private_ips = json::array!();
                    for ip_light in in_json["PrivateIps"].members() {
                        let private_ip = require_arg!(ip_light, "PrivateIp");
                        let is_primary = optional_arg!(ip_light, "IsPrimary", false);
                        let private_ip_block = json::object!{
                            PrivateDnsName: private_ip.clone().as_str().unwrap().to_owned() + ".eu-west-2.compute.internal",
                            PrivateIp: private_ip.clone(),
                            IsPrimary: is_primary.clone(),
                        };

                        if is_primary.as_bool().unwrap() {
                            if has_primary_in_req {
                                return bad_argument(req_id, json, "only one private ip can be set primary")
                            }
                            has_primary_in_req = true;
                            nic["PrivateDnsName"] = private_ip_block["PrivateDnsName"].clone();
                        }

                        let net_st: Result<Ipv4Addr, _> = private_ip.as_str().unwrap().parse();
                        match net_st {
                            Ok(range) => {
                                if !subnet_st.contains(&range) {
                                    return bad_argument(req_id, json, "private ip is not within the subnet range")
                                }
                                if used_ips.len() == usize::try_from(hosts_of_netmask(subnet_st.prefix_len())).unwrap() {
                                    return bad_argument(req_id, json, "all private ips used for subnet")
                                }
                                if used_ips.members().find(|ip| private_ip == **ip).is_some() {
                                    return bad_argument(req_id, json, "private ip already in use in subnet");
                                }
                                if private_ips.members().find(|ip_block| private_ip == ip_block["PrivateIp"]).is_some() {
                                    return bad_argument(req_id, json, "private ips need to be exclusive");
                                }

                                private_ips.push(private_ip_block).unwrap();
                            },
                            _ => return bad_argument(req_id, json, "you range is pure &@*$ i mean invalid")
                        }
                    }
                    nic["PrivateIps"] = private_ips.clone();
                }
                if !has_primary_in_req {
                    used_ips = used_ips_of_subnet!(&subnet_id);
                    let mut used_ips_req = json::array!();
                    for pip in nic["PrivateIps"].members() {
                        used_ips_req.push(pip["PrivateIp"].clone()).unwrap();
                    }
                    let mut hosts = subnet_st.hosts();
                    let private_ip = match hosts.find(|ip| used_ips.members().find(|used_ip| used_ip.as_str().unwrap() == ip.to_string()).is_none()
                                                      && used_ips_req.members().find(|used_ip| used_ip.as_str().unwrap() == ip.to_string()).is_none()) {
                        Some(pip) => pip,
                        _ => return bad_argument(req_id, json, "all private ips used")
                    };
                    let private_ip_block = json::object!{
                        PrivateDnsName: private_ip.to_string().to_owned() + ".eu-west-2.compute.internal",
                        PrivateIp: private_ip.to_string(),
                        IsPrimary: true,
                    };
                    nic["PrivateDnsName"] = private_ip_block["PrivateDnsName"].clone();
                    nic["PrivateIps"].push(private_ip_block).unwrap();
                }
                if in_json.has_key("SecurityGroupIds")  {
                    add_security_group!(in_json, req_id, nic);
                }

                main_json[user_id]["Nics"].push(nic.clone()).unwrap();
                json["Nic"] = nic.clone();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadNics => {
                check_aksk_auth!(auth);

                let nics = &main_json[user_id]["Nics"];

                json["Nics"] = (*nics).clone();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteNic => {
                check_aksk_auth!(auth);
                let nics = &mut main_json[user_id]["Nics"];
                let in_json = require_in_json!(bytes);
                let nic_id = require_arg!(in_json, "NicId");

                array_remove!(nics, |nic| nic_id == nic["NicId"]);
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::CreateNetPeering => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());

                let accepter_net_id = require_arg!(in_json, "AccepterNetId");
                let source_net_id = require_arg!(in_json, "SourceNetId");
                if accepter_net_id == source_net_id {
                    return bad_argument(req_id, json, format!("The provided value '{}' for parameter AccepterNetId is invalid. The values for AccepterNetId and SourceNetId must be different.", accepter_net_id).as_str())
                }

                let get_net_i = |net_id: &JsonValue| {
                    for (user_id, resources) in main_json.members().enumerate() {
                        if let Some (net) = resources["Nets"].members().find(|net| *net_id == net["NetId"]) {
                            return Some((user_id, net));
                        }
                    }
                    None
                };
                let (accepter_user_id, accepter_net) = match get_net_i(&accepter_net_id) {
                    Some ((i, net)) => (i, net),
                    _ => return bad_argument(req_id, json, format!("can't find user linked with accepter net id {}", accepter_net_id).as_str())
                };
                let (source_user_id, source_net) = match get_net_i(&source_net_id) {
                    Some ((i, net)) => (i, net),
                    _ => return bad_argument(req_id, json, format!("can't find user linked with source net id {}", source_net_id).as_str())
                };
                if source_user_id != user_id {
                    return bad_argument(req_id, json, format!("the source net id {} needs to be your own", source_net_id).as_str())
                }
                
                let mut net_peering = json::object!{
                    "Tags": [],
                    State: {
                        Message: "Pending acceptance by ".to_owned() + &format!("{:012x}", accepter_user_id),
                        "Name": "pending-acceptance"
                    },
                    AccepterNet: {
                        NetId: accepter_net_id.clone(),
                        IpRange: accepter_net["IpRange"].clone(),
                        AccountId: format!("{:012x}", accepter_user_id)
                    },
                    SourceNet: {
                        NetId: source_net_id.clone(),
                        IpRange: source_net["IpRange"].clone(),
                        AccountId: format!("{:012x}", source_user_id)
                    },
                    NetPeeringId: format!("pcx-{:08x}", req_id)
                };

                if main_json[source_user_id]["Vms"].len() == 0 || main_json[accepter_user_id]["Vms"].len() == 0 {
                    return bad_argument(req_id, json, "Peered Nets must contain at least one virtual machine (VM) each before the creation of the Net peering");
                }
                let get_net_peering = |source_net: &str, accepter_net: &str| main_json[source_user_id]["NetPeerings"].members().find(|net_p| source_net_id == net_p[source_net]["NetId"] && accepter_net_id == net_p[accepter_net]["NetId"]);
                
                if let Some (existing_net_peering) = get_net_peering("SourceNet", "AccepterNet") {
                    json["NetPeering"] = existing_net_peering.clone();
                    return Ok((jsonobj_to_strret(json, req_id), StatusCode::OK));
                }
                if let Some (reverse_net_peering) = get_net_peering( "AccepterNet", "SourceNet") {
                    if reverse_net_peering["State"]["Name"].as_str().unwrap() == "active" {
                        net_peering["State"]["Name"] = "rejected".into();
                        net_peering["State"]["Message"] = "Rejected automatically because active reverse link already exists".into();
                    }
                }

                let source_net_ip_range: Ipv4Net = source_net["IpRange"].as_str().unwrap().parse().unwrap();
                let accepter_net_ip_range: Ipv4Net = accepter_net["IpRange"].as_str().unwrap().parse().unwrap();
                // When a net_peering failed, the result is sent back but not stored
                if source_net_ip_range.contains(&accepter_net_ip_range) || accepter_net_ip_range.contains(&source_net_ip_range) {
                    net_peering["State"]["Name"] = "failed".into();
                    net_peering["State"]["Message"] = "The two Nets must not have overlapping IP ranges".into();
                }
                else {
                    main_json[source_user_id]["NetPeerings"].push(net_peering.clone()).unwrap();
                    if source_user_id != accepter_user_id {
                        main_json[accepter_user_id]["NetPeerings"].push(net_peering.clone()).unwrap();
                    }
                }
                json["NetPeering"] = net_peering.clone();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::ReadNetPeerings => {
                check_aksk_auth!(auth);

                let net_peerings = &main_json[user_id]["NetPeerings"];

                json["NetPeerings"] = (*net_peerings).clone();
                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::AcceptNetPeering => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());

                let net_peering_id = require_arg!(in_json, "NetPeeringId");

                let is_pending_net_p = |net_p: &JsonValue| {
                    net_peering_id == net_p["NetPeeringId"]
                    && &format!("{:012x}", user_id) == net_p["AccepterNet"]["AccountId"].as_str().unwrap()
                    && net_p["State"]["Name"].as_str().unwrap() == "pending-acceptance"
                };

                let mut updated = false;
                let mut existing_net_peering = json::JsonValue::new_object();
                for resources in main_json.members_mut() {
                    for net_peering in resources["NetPeerings"].members_mut() {
                        if is_pending_net_p(net_peering) {
                            net_peering["State"]["Name"] = "active".into();
                            net_peering["State"]["Message"] = "Active".into();
                            if !updated {
                                json["NetPeering"] = net_peering.clone();
                                existing_net_peering = net_peering.clone();
                                updated = true;
                            }
                        }
                    }
                }
                if !updated {
                    return bad_argument(req_id, json, "can't find a net peering pending-acceptance");
                }

                let is_reverse_net_p = |net_p: &JsonValue| {
                    net_p["AccepterNet"] == existing_net_peering["SourceNet"]
                    && net_p["SourceNet"] == existing_net_peering["AccepterNet"]
                    && net_p["State"]["Name"].as_str().unwrap() == "pending-acceptance"
                };

                for resources in main_json.members_mut() {
                    for net_peering in resources["NetPeerings"].members_mut() {
                        if is_reverse_net_p(net_peering) {
                            net_peering["State"]["Name"] = "rejected".into();
                            net_peering["State"]["Message"] = "Rejected automatically because active reverse link already exists".into();
                        }
                    }
                }

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::RejectNetPeering => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());

                let net_peering_id = require_arg!(in_json, "NetPeeringId");

                let net_peering = match main_json[user_id]["NetPeerings"].members_mut().find(|net_p| 
                    net_p["NetPeeringId"] == net_peering_id && net_p["State"]["Name"] == "pending-acceptance") 
                {
                    Some(net_p) => net_p,
                    None => return bad_argument(req_id, json, format!("can't find the net peering {} in pending-acceptance state", net_peering_id).as_str())
                };
                net_peering["State"]["Name"] = "rejected".into();
                net_peering["State"]["Message"] = "Rejected by user".into();

                Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
            },
            RicCall::DeleteNetPeering => {
                check_aksk_auth!(auth);
                let in_json = require_in_json!(bytes);
                println!("{:#}", in_json.dump());

                let net_peering_id = require_arg!(in_json, "NetPeeringId");
                let is_request_owner = |net_peering: &JsonValue| net_peering["SourceNet"]["AccountId"].as_str().unwrap() == &format!("{:012x}", user_id);
                let is_peer_net_owner = |net_peering: &JsonValue| net_peering["AccepterNet"]["AccountId"].as_str().unwrap() == &format!("{:012x}", user_id);

                let mut deleted = false;
                for resources in main_json.members_mut() {
                    if resources["NetPeerings"].members().any(|net_peering| {
                        net_peering_id == net_peering["NetPeeringId"] && 
                        (match net_peering["State"]["Name"].as_str().unwrap() {
                            "pending-acceptance" => is_request_owner(net_peering),
                            "active"  => is_request_owner(net_peering) || is_peer_net_owner(net_peering),
                            _ => false
                        })
                    }) {
                        array_remove!(resources["NetPeerings"], |net_peering| net_peering_id == net_peering["NetPeeringId"]);
                        deleted = true;
                    }
                }
                if !deleted {
                    return bad_argument(req_id, json, format!("cannot delete the net peering {}", net_peering_id).as_str())
                }
 
            Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
        },
        RicCall::CreateVirtualGateway => {
            check_aksk_auth!(auth);
            let in_json = require_in_json!(bytes);
            println!("{:#}", in_json.dump());

            let virtual_gateway = json::object!{
                VirtualGatewayId: format!("vgw-{:08x}", req_id),
                ConnectionType: require_arg!(in_json, "ConnectionType"),
                "NetToVirtualGatewayLinks": [],
                "State": "available",
                "Tags": []
            };
            if virtual_gateway["ConnectionType"] != "ipsec.1" {
                return bad_argument(req_id, json, "The type of VPN connection supported by the virtual gateway needs to be ipsec.1");
            }

            main_json[user_id]["VirtualGateways"].push(virtual_gateway.clone()).unwrap();
            json["VirtualGateway"] = virtual_gateway.clone();
            Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
        },
        RicCall::ReadVirtualGateways => {
            check_aksk_auth!(auth);

            let virtual_gateways = &main_json[user_id]["VirtualGateways"];

            json["VirtualGateways"] = (*virtual_gateways).clone();
            Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
        },
        RicCall::LinkVirtualGateway => {
            check_aksk_auth!(auth);
            let in_json = require_in_json!(bytes);
            println!("{:#}", in_json.dump());

            let virtual_gateway_id = require_arg!(in_json, "VirtualGatewayId");
            let net_id = require_arg!(in_json, "NetId");
            let _ = match get_by_id!("Nets", "NetId", net_id) {
                Ok(_) => (),
                _ => return bad_argument(req_id, json, "Net not found")
            };
            let virtual_gateway = match get_by_id!("VirtualGateways", "VirtualGatewayId", virtual_gateway_id) {
                Ok((_, idx)) => &mut main_json[user_id]["VirtualGateways"][idx],
                _ => return bad_argument(req_id, json, "Virtual Gateway not found")
            };

            if !virtual_gateway["NetToVirtualGatewayLinks"].is_empty() {
                return bad_argument(req_id, json, format!("Virtual Gateway {} is already linked to a Net", virtual_gateway_id).as_str())
            }
            let virtual_gateway_link = json::object!{
                "State": "attached",
                NetId: net_id 
            };
            virtual_gateway["NetToVirtualGatewayLinks"].push(virtual_gateway_link.clone()).unwrap();
            
            json["NetToVirtualGatewayLink"] = virtual_gateway_link.clone();
            Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
        },
        RicCall::UnlinkVirtualGateway => {
            check_aksk_auth!(auth);
            let in_json = require_in_json!(bytes);
            println!("{:#}", in_json.dump());

            let virtual_gateway_id = require_arg!(in_json, "VirtualGatewayId");
            let net_id = require_arg!(in_json, "NetId");

            let get_vgw_link_idx = || -> Option<(usize, usize)> {
                for (vgw_idx, vgw) in main_json[user_id]["VirtualGateways"].members().enumerate() {
                    if vgw["VirtualGatewayId"] == virtual_gateway_id {
                        for (link_idx, link) in vgw["NetToVirtualGatewayLinks"].members().enumerate() {
                            if link["NetId"] == net_id {
                                return Some ((vgw_idx, link_idx));
                            }
                        }
                    }
                }
                None
            };
            let (vgw_idx, link_idx) = match get_vgw_link_idx() {
                Some((vgw_idx, link_idx)) => (vgw_idx, link_idx),
                None => return bad_argument(req_id, json, format!("can't find link with net id {}", net_id).as_str())
            };
            
            main_json[user_id]["VirtualGateways"][vgw_idx]["NetToVirtualGatewayLinks"].array_remove(link_idx);
            Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
        },
        RicCall::DeleteVirtualGateway => {
            check_aksk_auth!(auth);
            let in_json = require_in_json!(bytes);
            println!("{:#}", in_json.dump());
            let virtual_gateways = &mut main_json[user_id]["VirtualGateways"];

            let virtual_gateway_id = require_arg!(in_json, "VirtualGatewayId");
            array_remove!(virtual_gateways, |vgw| vgw["VirtualGatewayId"] == virtual_gateway_id);

            Ok((jsonobj_to_strret(json, req_id), StatusCode::OK))
        }
    }
}
}

macro_rules! catch_ric_calls {
    ( $p:expr, $( $call:ident ),* ) => {
        match $p {
            "/" => Ok(RicCall::Root),
            $(
                concat!("/", stringify!($call)) | concat!("/api/v1/", stringify!($call)) | concat!("/api/latest/", stringify!($call)) => Ok(RicCall::$call),
            )*
            "/debug" => Ok(RicCall::Debug),
            _ => Err(())
        }
    };
}

impl FromStr for RicCall {
    type Err = ();
    fn from_str(path: &str) -> Result<Self, Self::Err> {
        println!("{}", path);
        let ps = remove_duplicate_slashes(path);
        let p = ps.as_str();

        println!("{}", p);
        catch_ric_calls!(
            p,
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
            CreateNatService,
            CreateSnapshot,
            CreateImageExportTask,
            CreateNic,
            CreateNetPeering,
            CreateClientGateway,
            DeleteClientGateway,
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
            DeleteNatService,
            DeleteSnapshot,
            DeleteImage,
            DeleteNic,
            DeleteNetPeering,
            ReadImageExportTasks,
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
            ReadNatServices,
            ReadSnapshots,
            ReadClientGateways,
            ReadVmTypes,
            ReadNics,
            ReadNetPeerings,
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
            UpdateImage,
            StartVms,
            StopVms,
            AcceptNetPeering,
            RejectNetPeering,
            ReadPublicCatalog,
            ReadRegions,
            ReadSubregions,
            ReadPublicIpRanges,
            CreateVirtualGateway,
            ReadVirtualGateways,
            LinkVirtualGateway,
            UnlinkVirtualGateway,
            DeleteVirtualGateway
        )
    }
}

fn which_v4_to_date(which_v4: & str) -> &str
{
    match which_v4 {
        "OSC4" => "X-Osc-Date",
        "AWS4" => "X-Amz-Date",
        _ => "X-Unknow-Date"
    }
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
            "headaches" => 1,
            "full" => 1,
            "mix" => 2,
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

                if auth_type < 1  || auth_type == 2 {
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

                /* 1rst secret key as key + date as data */
                let mut hmac = match HmacSha256::new_from_slice(format!("{}{}", which_v4, true_sk).as_bytes()) {
                    Ok(v) => v,
                    _ => return false
                };
                hmac.update(short_date.as_bytes());

                /* 2nd old hash as key + region as data */
                hmac =  match HmacSha256::new_from_slice(&hmac.finalize().into_bytes()) {
                    Ok(v) => v,
                    _ => return false
                };
                hmac.update(region.as_bytes());

                /*  3rd: old hash + api */
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
            println!("404 Unknow call {}", uri.path());
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
                    AccountId: format!("{:12x}", 0xffffff),
                    ImageId: format!("ami-{:08x}", 0xffffff00u32),
                    AccountAlias:"Outscale",
                    ImageName: "Fill More is for Penguin General",
                    State: "available",
                }
            },
            SecurityGroups: json::array!{
                json::object!{
                    Tags: json::array!{},
                    SecurityGroupId: format!("sg-{:08x}", 0xffffff00u32),
                    AccountId: format!("{:12x}", cnt_users),
                    OutboundRules: json::array!{},
                    InboundRules: json::array!{},
                    SecurityGroupName: "default",
                    Description: "default security group",
                }
            },
            NatServices: json::JsonValue::new_array(),
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
            LinkPublicIps: json::JsonValue::new_array(),
            Snapshots: json::JsonValue::new_array(),
            ClientGateways: json::JsonValue::new_array(),
            VirtualGateways: json::JsonValue::new_array(),
            ImageExportTasks: json::JsonValue::new_array(),
            NetPeerings: json::JsonValue::new_array(),
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
