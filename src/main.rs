use std::env;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::string::String;
use std::sync::atomic::{AtomicUsize, Ordering};
use futures::lock::Mutex;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Method, StatusCode};
use base64::{engine::general_purpose, Engine as _};
//use hyper::header::{Headers, Authorization};
use std::str::FromStr;
use std::fs;
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use simple_hyper_server_tls::*;
use openssl::rsa::Rsa;
use pem::{Pem, encode_config, EncodeConfig, LineEnding};
//use openssl::x509::X509;
//use openssl::hash::MessageDigest;

type HmacSha256 = Hmac<Sha256>;

fn jsonobj_to_strret(mut json: json::JsonValue, req_id: usize) -> String {
    json["ResponseContext"] = json::JsonValue::new_object();
    json["ResponseContext"]["RequestId"] = req_id.into();
    json::stringify_pretty(json, 3)
}

fn have_request_filter(filter: & json::JsonValue, vm: & json::JsonValue,
                       lookfor: & str, src: & str, old: bool) -> bool {
    if !old {
        return false;
    }

    if filter.has_key(lookfor) {

        for l in filter[lookfor].members() {
            if vm.has_key(src) && vm[src] == *l {
                return true;
            }
        }
        false
    } else {
        true
    }
}

fn bad_argument(req_id: usize ,mut json: json::JsonValue,
                error:  &str) ->
    Result<Response<Body>,Infallible> {
    let mut response = Response::new(Body::empty());

    json["Error"] = error.into();
    *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
    return Ok(response);

}

fn bad_auth(error: String) -> Result<Response<Body>,Infallible> {
    let mut response = Response::new(Body::empty());

    response.headers_mut().append("WWW-Authenticate", "Basic".parse().unwrap());
    *response.body_mut() = Body::from(error);
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    return Ok(response)
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
enum RicCall {
    Root,
    Debug,
    CreateNet,
    CreateKeypair,
    ReadKeypairs,
    DeleteKeypair,
    ReadAccessKeys,
    CreateVms,
    ReadVms,
    DeleteVms,
    CreateTags,
    CreateFlexibleGpu,
    CreateImage,
    ReadImages,
    ReadLoadBalancers,
    ReadFlexibleGpus
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
            "/DeleteKeypair" | "/api/v1/DeleteKeypair" | "/api/latest/DeleteKeypair" =>
                Ok(RicCall::DeleteKeypair),
            "/ReadAccessKeys" | "/api/v1/ReadAccessKeys" | "/api/latest/ReadAccessKeys" =>
                Ok(RicCall::ReadAccessKeys),
            "/ReadVms" | "/api/v1/ReadVms" | "/api/latest/ReadVms" =>
                Ok(RicCall::ReadVms),
            "/CreateVms" | "/api/v1/CreateVms" | "/api/latest/CreateVms" =>
                Ok(RicCall::CreateVms),
            "/DeleteVms" | "/api/v1/DeleteVms" | "/api/latest/DeleteVms" =>
                Ok(RicCall::DeleteVms),
            "/ReadFlexibleGpus" |"/api/v1/ReadFlexibleGpus" | "/api/latest/ReadFlexibleGpus" =>
                Ok(RicCall::ReadFlexibleGpus),
            "/CreateTags" | "/api/v1/CreateTags" | "/api/latest/CreateTags" =>
                Ok(RicCall::CreateTags),
            "/CreateFlexibleGpu" | "/api/v1/CreateFlexibleGpu" | "/api/latest/CreateFlexibleGpu" =>
                Ok(RicCall::CreateFlexibleGpu),
            "/CreateImage" | "/api/v1/CreateImage" | "/api/latest/CreateImage" =>
                Ok(RicCall::CreateImage),
            "/ReadImages" | "/api/v1/ReadImages" | "/api/latest/ReadImages" =>
                Ok(RicCall::ReadImages),
            "/ReadLoadBalancers" | "/api/v1/ReadLoadBalancers" | "/api/latest/ReadLoadBalancers" =>
                Ok(RicCall::ReadLoadBalancers),
            "/CreateNet" | "/api/v1/CreateNet" | "/api/latest/CreateNet" =>
                Ok(RicCall::CreateNet),
            "/debug" => Ok(RicCall::Debug),
            _ => Err(())
        }
    }
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
    let mut response = Response::new(Body::empty());
    let mut json = json::JsonValue::new_object();
    let mut main_json = connection.lock().await;
    let cfg = cfg.lock().await;
    let headers = req.headers().clone();
    let mut user_id = 0;
    let method = req.method().clone();
    let uri = req.uri().clone();
    let bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let users = &cfg["users"];

    println!("in handler");
    if cfg["auth_type"] != "none" {
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
                println!("Authorization not found");
                return bad_auth("\"Authorization Header require\"".to_string());
            }
        };
        let mut error_msg = "\"Unknow user\"".to_string();

        if userpass.starts_with("Basic ") {
            let based = userpass.strip_prefix("Basic ").unwrap();
            let decoded = general_purpose::STANDARD
                .decode(based).unwrap();
            let stringified = std::str::from_utf8(&decoded).unwrap();
            let tupeled = stringified.split_once(":").unwrap();

            match users.members().position(|u| {
                let ret = u["login"] == tupeled.0;
                if auth_type < 1 {
                    return ret;
                }
                return u["pass"] == tupeled.1;
            }) {
                Some(idx) => user_id = idx,
                _ => {
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    *response.body_mut() = Body::from(error_msg);
                    return Ok(response)
                }
            }
        } else if userpass.starts_with("OSC4-HMAC-SHA256") {
            let cred = userpass.strip_prefix("OSC4-HMAC-SHA256 ").unwrap();
            let cred = match cred.strip_prefix("Credential=") {
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

                if auth_type < 1 || ret == false {
                    return ret;
                }

                let true_sk = match u["secret_key"].as_str() {
                    Some(v) => v,
                    _ => return v4_error_ret(&mut error_msg, "fail to get secret_key")
                };
                let x_date = match headers.get("X-Osc-Date") {
                    Some(x_date) => {
                        x_date.to_str().unwrap().to_string()
                    }
                    _ =>  {
                        println!("X-Osc-Date not found");
                        return v4_error_ret(&mut error_msg, "X-Osc-Date not found");
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
                let api = tuple_cred.0;
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
                let str_to_sign = format!("OSC4-HMAC-SHA256
{}
{}
{:x}", x_date, credential_scope, canonical_request_sha);

                let mut hmac = match HmacSha256::new_from_slice(format!("OSC4{}", true_sk).as_bytes()) {
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

                return format!("{:x}", signature.clone().into_bytes()) == send_signature;

            }) {
                Some(idx) => user_id = idx,
                _ => {
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    *response.body_mut() = Body::from(error_msg);
                    return Ok(response)
                }
            }

        } else {
            return bad_auth("\"Authorization Header wrong Format\"".to_string());
        }
    }
    // match (req.method(), req.uri().path())
    match (&method, RicCall::from_str(uri.path())) {
        (&Method::GET, Ok(RicCall::Root)) => {
            *response.body_mut() = Body::from("Try POSTing to /ReadVms");
        },
        (&Method::POST, Ok(RicCall::Debug)) => {
            let hdr = format!("{:?}", headers);
            *response.body_mut() = Body::from(format!("data: {}\nheaders: {}\n",
                                                      String::from_utf8(bytes.to_vec()).unwrap(),
                                                      hdr));
        },
        (&Method::POST, Ok(RicCall::ReadVms))  => {

            let user_vms = &main_json[user_id]["Vms"];

            json["Vms"] = (*user_vms).clone();

            if !bytes.is_empty() {
                let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                match in_json {
                    Ok(in_json) => {
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
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::DeleteVms))  => {

            let user_vms = &mut main_json[user_id]["Vms"];

            json["Vms"] = (*user_vms).clone();

            if !bytes.is_empty() {
                let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                match in_json {
                    Ok(in_json) => {
                        if in_json.has_key("VmIds") {
                            let ids = &in_json["VmIds"];

                            json["Vms"] = json::JsonValue::new_array();
                            let mut idx = 0;
                            let mut rm_array = vec![];
                            for vm in user_vms.members() {
                                let mut need_rm = true;

                                for id in ids.members() {
                                    if *id == vm["VmId"] {
                                        need_rm = true;
                                    }
                                }
                                if need_rm {
                                    json["Vms"].push((*vm).clone()).unwrap();
                                    rm_array.push(idx);
                                }
                                idx += 1;
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
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::DeleteKeypair))  => {

            let user_kps = &mut main_json[user_id]["Keypairs"];

            if !bytes.is_empty() {
                let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                match in_json {
                    Ok(in_json) => {
                        if in_json.has_key("KeypairName") {
                            let name = &in_json["KeypairName"];

                            let mut idx = 0;
                            let mut rm = false;
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
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::CreateImage)) => {
            let image_id = format!("ami-{:08}", req_id);
            let mut image = json::object!{
                AccountId: user_id,
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
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::CreateNet)) => {
            let net_id = format!("vpc-{:08}", req_id);
            let mut net = json::object!{
                NetId: net_id
            };

            if !bytes.is_empty() {
                let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                match in_json {
                    Ok(in_json) => {
                        if in_json.has_key("IpRange") {
                            net["IpRange"] = in_json["IpRange"].clone();
                        } else {
                            return bad_argument(req_id, json, "l'IpRange wesh !");
                        }
                    },
                    Err(_) => {
                        return bad_argument(req_id, json, "Invalide json");
                    }
                }
            } else {
                return bad_argument(req_id, json, "l'IpRange wesh !");
            }
            main_json[user_id]["Nets"].push(
                net.clone()).unwrap();
            json["Nets"] = json::array!{net};
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::ReadKeypairs))  => {

            let user_kps = &main_json[user_id]["Keypairs"];

            let mut kps = (*user_kps).clone();

            for k in kps.members_mut() {
                k.remove("PrivateKey");
            }
            json["Keypairs"] = kps;

            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::ReadAccessKeys))  => {

            json["AccessKeys"] = json::array![
                json::object!{
                    State:"ACTIVE",
                    AccessKeyId: users[user_id]["access_key"].clone(),
                    CreationDate:"2020-01-28T10:58:41.000Z",
                    LastModificationDate:"2020-01-28T10:58:41.000Z"
            }];

            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::ReadImages))  => {

            let user_imgs = &main_json[user_id]["Images"];

            json["Images"] = (*user_imgs).clone();

            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::ReadLoadBalancers))  => {

            let user_vms = &main_json[user_id]["LoadBalancers"];

            json["LoadBalancers"] = (*user_vms).clone();

            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::ReadFlexibleGpus))  => {

            let user_fgpus = &main_json[user_id]["FlexibleGpus"];

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
                    *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
                },
        (&Method::POST, Ok(RicCall::CreateKeypair)) => {
            let mut kp = json::object!{};
            match json::parse(std::str::from_utf8(&bytes).unwrap()) {
                Ok(in_json) => {
                    if in_json.has_key("KeypairName") {
                        let name = in_json["KeypairName"].to_string();
                        for k in main_json[user_id]["Keypairs"].members() {
                            if k["KeypairName"].to_string() == name {
                                return bad_argument(req_id, json, "KeypairName Name conflict")
                            }
                        }
                        kp["KeypairName"] = json::JsonValue::String(name);
                        let rsa = Rsa::generate(2048).unwrap();

                        // let public_key = rsa.public_key_to_der().unwrap();
                        let private_key = rsa.private_key_to_der().unwrap();
                        //let public_keyu8: &[u8] = &private_key; // c: &[u8]
                        // let x509 = X509::from_der(&public_key).unwrap();

                        let private_pem = Pem::new("RSA PRIVATE KEY", private_key);
                        let private = encode_config(&private_pem, EncodeConfig { line_ending: LineEnding::LF });

                        kp["PrivateKey"] = json::JsonValue::String(private);
                        //json["KeypairFingerprint"] = json::JsonValue::String(x509.digest(MessageDigest::md5()).unwrap().escape_ascii().to_string());
                    } else {
                        return bad_argument(req_id, json, "KeypairName Missing")
                    }
                },
                Err(_) => {
                    return bad_argument(req_id, json, "Invalid JSON format")
                }
            };

            main_json[user_id]["Keypairs"].push(
                kp.clone()).unwrap();
            json["Keypair"] = kp;
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::CreateVms)) => {
            let vm_id = format!("i-{:08}", req_id);
            let vm = json::object!{
                    VmType: "small",
                    VmId: vm_id
                };

            main_json[user_id]["Vms"].push(
                vm.clone()).unwrap();
            json["Vms"] = json::array!{vm};
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::CreateTags)) => {
            if bytes.is_empty() {
                return bad_argument(req_id, json, "Create Tags require: 'ResourceIds', 'Tags' argument");
            }

            let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
            match in_json {
                Ok(in_json) => {
                    println!("{:#}", in_json.dump());
                    if !in_json.has_key("Tags") && !in_json.has_key("ResourceIds") {
                        return bad_argument(req_id, json, "Create Tags require: ResourceIds, Tags argument");
                    }
                },
                Err(_) => {
                    return bad_argument(req_id, json, "Invalide json");
                }
            }
            println!("CreateTags");
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::CreateFlexibleGpu)) => {
            let user_fgpu = &mut main_json[user_id]["FlexibleGpus"];
            let fgpu_json = json::object!{
                DeleteOnVmDeletion: false,
                FlexibleGpuId: format!("fgpu-{:08}", req_id),
                Generation: "Wololo",
                ModelName: "XOXO",
                State: "imaginary",
                SubregionName: "yes",
                VmId: "unlink"
            };


            println!("CreateFlexibleGpu {:#}", fgpu_json.dump());
            json["FlexibleGpu"] = json::array!{fgpu_json.clone()};
            user_fgpu.push(fgpu_json).unwrap();
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        _ => {
            println!("Unknow call {}", uri.path());
            *response.status_mut() = StatusCode::NOT_FOUND;
       },
    };

    Ok(response)
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
    let cfg = match fs::read_to_string(&usr_cfg_path) {
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
    println!("{:#}", cfg.dump());
    let mut connection = json::JsonValue::new_array();
    for _m in cfg["users"].members() {
        connection.push(json::object!{
            Vms: json::JsonValue::new_array(),
            FlexibleGpus: json::JsonValue::new_array(),
            LoadBalancers: json::JsonValue::new_array(),
            Images: json::JsonValue::new_array(),
            Nets: json::JsonValue::new_array(),
            Keypairs: json::JsonValue::new_array(),
        }).unwrap();
    }
    let tls = match cfg["tls"] == true {
        true => true,
        _ => false
    };
    let connection = Mutex::new(connection);
    let connection = Arc::new(connection);
    let cfg = Arc::new(Mutex::new(cfg));
    let requet_id = Arc::new(AtomicUsize::new(0));

    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let any_server = match tls {
        true => match hyper_from_pem_files("cert.pem", "key.pem", Protocols::ALL, &addr) {
            Ok(server) => server.serve(
                make_service_fn( move |_| { // first move it into the closure
                    // closure can be called multiple times, so for each call, we must
                    // clone it and move that clone into the async block
                    println!("before handler -1");
                    let connection = connection.clone();
                    let requet_id = requet_id.clone();
                    let cfg = cfg.clone();
                    async move {
                        // async block is only executed once, so just pass it on to the closure
                        Ok::<_, hyper::Error>(service_fn( move |_req| {
                            let connection =  connection.clone();
                            let id = requet_id.fetch_add(1, Ordering::Relaxed);
                            let cfg = cfg.clone();
                            println!("before handler");
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
