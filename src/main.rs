use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::string::String;
use std::sync::atomic::{AtomicUsize, Ordering};
use futures::lock::Mutex;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Method, StatusCode};
use std::str::FromStr;

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
    ReadVms,
    Debug,
    CreateVms,
    CreateTags,
    CreateFlexibleGpu
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
                 req_id: usize) -> Result<Response<Body>, Infallible> {
    let mut response = Response::new(Body::empty());
    let mut json = json::JsonValue::new_object();
    let mut main_json = connection.lock().await;
    let user_id = 0;

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
        (&Method::POST, Ok(RicCall::CreateVms)) => {
            let vm_id = format!("i-{:08}", req_id);
            main_json[user_id]["Vms"].push(
                json::object!{
                    VmType: "small",
                    VmId: vm_id
                }).unwrap();
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
            json["FlexibleGpu"] = fgpu_json;
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

    let mut connection = json::JsonValue::new_array();
    connection[0] = json::object!{
        Vms: json::JsonValue::new_array(),
        FlexibleGpu: json::JsonValue::new_array()
    };
    let connection = Mutex::new(connection);
    let connection = Arc::new(connection);
    let requet_id = Arc::new(AtomicUsize::new(0));

    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let make_svc = make_service_fn( move |_| { // first move it into the closure
    // closure can be called multiple times, so for each call, we must
        // clone it and move that clone into the async block
        let connection = connection.clone();
        let requet_id = requet_id.clone();
     async move {
        // async block is only executed once, so just pass it on to the closure
        Ok::<_, hyper::Error>(service_fn( move |_req| {
            let connection =  connection.clone();
            let id = requet_id.fetch_add(1, Ordering::Relaxed);
            // but this closure may also be called multiple times, so make
            // a clone for each call, and move the clone into the async block
            async move { handler(_req, &connection, id).await }
        }))
     }
    });
    /*let make_svc = make_service_fn(|_conn| async {
        // service_fn converts our function into a `Service`
        Ok::<_, Infallible>(service_fn(handler))
    });*/

    let server = Server::bind(&addr).serve(make_svc);

    // Run this server for... forever!
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
