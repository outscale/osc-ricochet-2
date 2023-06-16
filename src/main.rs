use std::env;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::string::String;
use std::sync::atomic::{AtomicUsize, Ordering};
use futures::lock::Mutex;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::{StatusCode};
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
    (String, hyper::StatusCode) {
        eprintln!("bad_argument: {}", error);
        json["Errors"] = json::array![json::object!{Details: error}];
        (jsonobj_to_strret(json, req_id), StatusCode::from_u16(400).unwrap())
}

fn bad_auth(error: String) -> Result<Response<Body>,Infallible> {
    let mut response = Response::new(Body::empty());

    eprintln!("bad_auth: {}", error);
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

fn try_conver_response(res: (String, StatusCode), need_convert: bool) -> (String, hyper::StatusCode) {
    if need_convert == false {
        return res
    }

    let mut xml_builder = XmlBuilder::default();
    let xml = xml_builder.build_from_json_string(res.0.as_str());

    return (xml.unwrap(), StatusCode::OK)
}

#[derive(Debug)]
enum RicCall {
    Root,
    Debug,

    CreateNet,
    CreateKeypair,
    CreateVms,
    DeleteVms,
    CreateTags,
    CreateFlexibleGpu,
    CreateImage,

    DeleteKeypair,

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

    // Free Calls
    ReadPublicCatalog,
    ReadRegions,
    ReadPublicIpRanges
}

impl RicCall {
    fn is_free(&self) -> bool {
        match *self {
            RicCall::ReadPublicCatalog => true,
            RicCall::ReadRegions => true,
            RicCall::ReadPublicIpRanges => true,
            _ => false
        }
    }

    fn eval(&self,
            mut main_json: futures::lock::MutexGuard<'_, json::JsonValue, >,
            cfg: futures::lock::MutexGuard<'_, json::JsonValue, >,
            bytes: hyper::body::Bytes,
            user_id: usize,
            req_id: usize,
            headers: hyper::HeaderMap<hyper::header::HeaderValue>,
            unauth : bool)
            -> (String, hyper::StatusCode) {
        let mut json = json::JsonValue::new_object();
        let users = &cfg["users"];
        //let mut ret = ("could not happen", StatusCode::NOT_IMPLEMENTED);

        println!("RicCall eval: {:?}", *self);
        if unauth && !self.is_free() {
            eprintln!("{:?} require auth", *self);
            return bad_argument(req_id, json, format!("{:?} require auth", *self).as_str())
        }

        match *self {
            RicCall::Root => {
                ("Try POSTing to /ReadVms".to_string(), StatusCode::OK)
            },
            RicCall::Debug => {
                let hdr = format!("{:?}", headers);
                (format!("data: {}\nheaders: {}\n",
                               String::from_utf8(bytes.to_vec()).unwrap(),
                               hdr), StatusCode::OK)
            },
            RicCall::ReadVms  => {

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
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::DeleteVms  => {

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
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
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
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::CreateImage => {
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
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::CreateNet => {
                let net_id = format!("vpc-{:08}", req_id);
                let mut net = json::object!{
                    NetId: net_id
                };

                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Ok(in_json) => {
                            if in_json.has_key("IpRange") {
                                let iprange = in_json["IpRange"].as_str().unwrap();

                                let net_st: Result<Ipv4Net, _> = iprange.parse();

                                match net_st {
                                    Ok(range) => {
                                        if range.prefix_len() != 16 && range.prefix_len() != 28 {
                                            return bad_argument(req_id, json, "iprange size is nope")
                                        }
                                        net["IpRange"] = iprange.clone().into()
                                    },
                                    _ => return bad_argument(req_id, json,
                                                             "you range is pure &@*$ i meam invalide")
                                }
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
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadKeypairs => {

                let user_kps = &main_json[user_id]["Keypairs"];

                let mut kps = (*user_kps).clone();

                for k in kps.members_mut() {
                    k.remove("PrivateKey");
                }
                json["Keypairs"] = kps;

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadNets => {

                let user_nets = &main_json[user_id]["Nets"];

                json["Nets"] = (*user_nets).clone();

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadAccessKeys => {

                json["AccessKeys"] = json::array![
                    json::object!{
                        State:"ACTIVE",
                        AccessKeyId: users[user_id]["access_key"].clone(),
                        CreationDate:"2020-01-28T10:58:41.000Z",
                        LastModificationDate:"2020-01-28T10:58:41.000Z"
                    }];

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
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

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadPublicIpRanges  => {

                json["PublicIps"] = json::array![
                    "43.41.44.22/24",
                    "34.14.44.22/24"
                ];

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadRegions  => {

                json["Regions"] = json::array![
                    json::object!{
                        Endpoint: "127.0.0.1:3000",
                        RegionName: "mud-half-3"
                    }
                ];

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
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

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadImages  => {

                let user_imgs = &main_json[user_id]["Images"];
                if !bytes.is_empty() {
                    let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                    match in_json {
                        Err(_) => {
                            return bad_argument(req_id, json, "Invalid JSON format")
                        },
                        Ok(in_json) => {
                            if in_json.has_key("Filters") {
                                let filters = in_json["Filters"].clone();
                            }
                        }
                    }
                }
                json["Images"] = (*user_imgs).clone();

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadDirectLinks  => {

                let user_dl = &main_json[user_id]["DirectLinks"];

                json["DirectLinks"] = (*user_dl).clone();

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadVolumes  => {

                let user_imgs = &main_json[user_id]["Volumes"];

                json["Volumes"] = (*user_imgs).clone();

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadLoadBalancers  => {

                let user_vms = &main_json[user_id]["LoadBalancers"];

                json["LoadBalancers"] = (*user_vms).clone();

                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadConsumptionAccount  => {
                println!("RicCall::ReadConsumptionAccount !!!");
                (jsonobj_to_strret(json::object!{
                    ConsumptionEntries:
                    json::array!{
                        json::object!{
                            AccountId: user_id,
                            Value: 0
                        }
                    }
                }, req_id), StatusCode::OK)
            },
            RicCall::ReadFlexibleGpus  => {

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
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::CreateKeypair => {
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
                }
                main_json[user_id]["Keypairs"].push(
                    kp.clone()).unwrap();
                json["Keypair"] = kp;
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::CreateVms => {
                let vm_id = format!("i-{:08}", req_id);
                let vm = json::object!{
                    VmType: "small",
                    VmId: vm_id
                };

                main_json[user_id]["Vms"].push(
                    vm.clone()).unwrap();
                json["Vms"] = json::array!{vm};
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::CreateTags => {
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
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::ReadQuotas => {
                json["QuotaTypes"] = json::array![
                    json::object!{
                        Quotas: json::array![
                            json::object!{
                                ShortDescription: "VM Limit",
                                QuotaCollection: "Compute",
                                AccountId: user_id,
                                Description: "Maximum number of VM this user can own",
                                MaxValue: "not implemented",
                                UsedValue: "not implemented",
                                Name: "bypass_group_size_limit"
                            },
                            json::object!{
                                ShortDescription: "Bypass Group Size Limit",
                                QuotaCollection: "Other",
                                AccountId: user_id,
                                Description: "Maximum size of a bypass group",
                                MaxValue: "not implemented",
                                UsedValue: "not implemented",
                                Name: "bypass_group_size_limit"
                            }
                        ],
                        QuotaType: "global"
                    }];
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
            },
            RicCall::CreateFlexibleGpu => {
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
                (jsonobj_to_strret(json, req_id), StatusCode::OK)
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
            "/ReadConsumptionAccount" |"/api/v1/ReadConsumptionAccount" | "/api/latest/ReadConsumptionAccount" =>
                Ok(RicCall::ReadConsumptionAccount),
            "/CreateTags" | "/api/v1/CreateTags" | "/api/latest/CreateTags" =>
                Ok(RicCall::CreateTags),
            "/CreateFlexibleGpu" | "/api/v1/CreateFlexibleGpu" | "/api/latest/CreateFlexibleGpu" =>
                Ok(RicCall::CreateFlexibleGpu),
            "/CreateImage" | "/api/v1/CreateImage" | "/api/latest/CreateImage" =>
                Ok(RicCall::CreateImage),
            "/ReadAccounts" | "/api/v1/ReadAccounts" | "/api/latest/ReadAccounts" =>
                Ok(RicCall::ReadAccounts),
            "/ReadImages" | "/api/v1/ReadImages" | "/api/latest/ReadImages" =>
                Ok(RicCall::ReadImages),
            "/ReadDirectLinks" | "/api/v1/ReadDirectLinks" | "/api/latest/ReadDirectLinks" =>
                Ok(RicCall::ReadDirectLinks),
            "/ReadVolumes" | "/api/v1/ReadVolumes" | "/api/latest/ReadVolumes" =>
                Ok(RicCall::ReadVolumes),
            "/ReadLoadBalancers" | "/api/v1/ReadLoadBalancers" | "/api/latest/ReadLoadBalancers" =>
                Ok(RicCall::ReadLoadBalancers),
            "/ReadPublicCatalog" | "/api/v1/ReadPublicCatalog" | "/api/latest/ReadPublicCatalog" =>
                Ok(RicCall::ReadPublicCatalog),
            "/ReadRegions" | "/api/v1/ReadRegions" | "/api/latest/ReadRegions" =>
                Ok(RicCall::ReadRegions),
            "/ReadPublicIpRanges" | "/api/v1/ReadPublicIpRanges" | "/api/latest/ReadPublicIpRanges" =>
                Ok(RicCall::ReadPublicIpRanges),
            "/ReadQuotas" | "/api/v1/ReadQuotas" | "/api/latest/ReadQuotas" =>
                Ok(RicCall::ReadQuotas),
            "/ReadNets" | "/api/v1/ReadNets" | "/api/latest/ReadNets" =>
                Ok(RicCall::ReadNets),
            "/CreateNet" | "/api/v1/CreateNet" | "/api/latest/CreateNet" =>
                Ok(RicCall::CreateNet),
            "/debug" => Ok(RicCall::Debug),
            _ => Err(())
        }
    }
}

fn which_v4_to_date<'a>(which_v4: & 'a String) -> &'a str
{
    if which_v4 == "OSC4" {
        return "X-Osc-Date"
    } else if which_v4 == "AWS4" {
        return "X-Amz-Date"
    }
    return "X-Unknow-Date"
}

fn clasify_v4<'a>(userpass: & 'a String) ->  Option<(&'a str, String)>
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
    let mut unauth = false;
    let uri = req.uri().clone();
    let mut bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let users = &cfg["users"];
    let mut out_convertion = false;
    let mut api = "api".to_string();

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
                unauth = true;
                "".to_string()
            }
        };
        let mut error_msg = "\"Unknow user\"".to_string();
        let cred = clasify_v4(&userpass);

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
        } else if cred != None {
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

                if ret == false {
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

                return format!("{:x}", signature.clone().into_bytes()) == send_signature;

            }) {
                Some(idx) => user_id = idx,
                _ => {
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    *response.body_mut() = Body::from(error_msg);
                    return Ok(response)
                }
            }

        } else if !unauth {
            return bad_auth("\"Authorization Header wrong Format\"".to_string());
        }
    }

    let to_call = match cfg["in_convertion"] == true {
        true => {
            let ret = match uri.path() {
                "/" | "/icu/" | "directlinks" | "fcu" => {

                    let mut in_args = json::JsonValue::new_object();
                    let args_str = std::str::from_utf8(&bytes).unwrap();
                    let mut path = uri.path().clone();

                    if path.contains("icu") {
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
                    } else if api != "api" || unauth == true {
                        let split = args_str.split('&');
                        for s in split {
                            let mut split = s.split('=');
                            let key = split.nth(0).unwrap();
                            let val = split.nth(0);

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
                unauth
            ), out_convertion);
            let mut response = Response::new(Body::empty());
            if api == "directlink" {
                response.headers_mut().append("x-amz-requestid", req_id.to_string().parse().unwrap());
            }
            *response.status_mut() = res.1;
            *response.body_mut() = Body::from(res.0);
            return Ok(response)
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
            DirectLinks: json::JsonValue::new_array(),
            Nets: json::JsonValue::new_array(),
            Volumes: json::JsonValue::new_array(),
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
