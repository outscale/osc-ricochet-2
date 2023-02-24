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
    CreateVms,
    ReadVms,
    CreateTags,
    CreateFlexibleGpu,
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
            "/ReadVms" | "/api/v1/ReadVms" | "/api/latest/ReadVms" => Ok(RicCall::ReadVms),
            "/CreateVms" | "/api/v1/CreateVms" | "/api/latest/CreateVms" => Ok(RicCall::CreateVms),
            "/ReadFlexibleGpus" |"/api/v1/ReadFlexibleGpus" | "/api/latest/ReadFlexibleGpus" => Ok(RicCall::ReadFlexibleGpus),
            "/CreateTags" | "/api/v1/CreateTags" | "/api/latest/CreateTags" => Ok(RicCall::CreateTags),
            "/CreateFlexibleGpu" | "/api/v1/CreateFlexibleGpu" | "/api/latest/CreateFlexibleGpu" => Ok(RicCall::CreateFlexibleGpu),
            "/debug" => Ok(RicCall::Debug),
            _ => Err(())
        }
    }
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
    let headers = req.headers();
    let mut user_id = 0;

    if cfg["auth_type"] != "none" {
        let users = &cfg["users"];
        let userpass = match headers.get("Authorization") {
            Some(auth) => {
                println!("{}", auth.to_str().unwrap());
                auth.to_str().unwrap().to_string()
            }
            _ =>  {
                println!("Authorization not found");
                response.headers_mut().append("WWW-Authenticate", "Basic".parse().unwrap());
                *response.body_mut() = Body::from("\"Authorization Header require\"");
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                return Ok(response)
            }
        };

        if userpass.starts_with("Basic ") {
            let based = userpass.strip_prefix("Basic ").unwrap();
            let decoded = general_purpose::STANDARD
                .decode(based).unwrap();
            let stringified = std::str::from_utf8(&decoded).unwrap();
            let tupeled = stringified.split_once(":").unwrap();

            println!("{}", stringified);
            println!("{} - {}", tupeled.0, tupeled.1);
            match users.members().position(|u| u["login"] == tupeled.0) {
                Some(idx) => user_id = idx,
                _ => {
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    *response.body_mut() = Body::from("\"Unknow user\"");
                    return Ok(response)
                }
            }
            println!("{:?}", user_id);
        }
    }

    // match (req.method(), req.uri().path())
    match (req.method(), RicCall::from_str(req.uri().path())) {
        (&Method::GET, Ok(RicCall::Root)) => {
            *response.body_mut() = Body::from("Try POSTing to /ReadVms");
        },
        (&Method::POST, Ok(RicCall::Debug)) => {
            let hdr = format!("{:?}", req.headers());
            let bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
            *response.body_mut() = Body::from(format!("data: {}\nheaders: {}\n",
                                                      String::from_utf8(bytes.to_vec()).unwrap(),
                                                      hdr));
        },
        (&Method::POST, Ok(RicCall::ReadVms))  => {

            let bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
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
                        json["Error"] = "Invalid JSON format".into();
                        *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
                        return Ok(response);
                    }
                }
            }
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::ReadFlexibleGpus))  => {

            let bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
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
                                json["Error"] = "Invalid JSON format".into();
                                *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
                                return Ok(response);
                            }
                        }
                    }
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
            let bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();

            if !bytes.is_empty() {
                println!("pas empty !");
                let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                match in_json {
                    Ok(in_json) => {
                        println!("{:#}", in_json.dump());
                    },
                    Err(_) => {
                        json["Error"] = "Invalid JSON format".into();
                        *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
                        return Ok(response);
                    }
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
            FlexibleGpus: json::JsonValue::new_array()
        }).unwrap();
    }
    let connection = Mutex::new(connection);
    let connection = Arc::new(connection);
    let cfg = Arc::new(Mutex::new(cfg));
    let requet_id = Arc::new(AtomicUsize::new(0));

    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let make_svc = make_service_fn( move |_| { // first move it into the closure
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
    });

    let server = Server::bind(&addr).serve(make_svc);

    // Run this server for... forever!
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
