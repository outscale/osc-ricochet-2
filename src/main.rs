use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::string::String;
use std::sync::atomic::{AtomicUsize, Ordering};
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Method, StatusCode};
use std::str::FromStr;

fn jsonobj_to_strret(mut json: json::JsonValue, req_id: usize) -> String {
    json["ResponseContext"] = json::JsonValue::new_object();
    json["ResponseContext"]["RequestId"] = req_id.into();
    json::stringify_pretty(json, 3)
}

fn request_filter_add(filter: & json::JsonValue, req: &mut String, need_and: &mut bool, lookfor: & str, src: & str) {
    if filter.has_key(lookfor) {
        let mut id = String::from(json::stringify(filter[lookfor].clone()));

        id.pop();
        id.remove(0);
        if *need_and {
            req.push_str(" AND")
        } else {
            req.push_str(" WHERE")
        }
        req.push_str(&format!(" {} IN ({})", src, id));
        *need_and = true;
        println!("{}", req)
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
                 connection: & sqlite::ConnectionWithFullMutex,
                 req_id: usize) -> Result<Response<Body>, Infallible> {
    let mut response = Response::new(Body::empty());
    let mut json = json::JsonValue::new_object();

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
            let mut query = String::from("SELECT * FROM Vms");

            if !bytes.is_empty() {
                println!("pas empty !");
                let in_json = json::parse(std::str::from_utf8(&bytes).unwrap());
                match in_json {
                    Ok(in_json) => {
                        let mut need_and = false;
                        println!("{:?}", in_json);
                        if in_json.has_key("Filters") {
                            let filter = &in_json["Filters"];
                            request_filter_add(filter, &mut query, &mut need_and, "VmIds", "Id");
                            request_filter_add(filter, &mut query,
                                               &mut need_and, "TagValues", "VmType");
                            request_filter_add(filter, &mut query, &mut need_and, "TagKeys", "Id");
                        }
                    },
                    Err(_) => {
                        json["Error"] = "Invalid JSON format".into();
                        *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
                        return Ok(response);
                    }
                }
            }
            json["Vms"] = json::JsonValue::new_array();
            connection
                .iterate(query, |pairs| {
                    let mut vm = json::JsonValue::new_object();
                    for &(id, t) in pairs.iter() {
                        match id {
                            "Id" => {
                                vm["VmId"] = t.unwrap().into();
                            },
                            "VmType" => vm["VmType"] = t.unwrap().into(),
                            _ => println!("{} not a Vm element", id),
                        }
                    }
                    json["Vms"].push(vm).unwrap();
                    true
                }).unwrap();
            *response.body_mut() = Body::from(jsonobj_to_strret(json, req_id));
        },
        (&Method::POST, Ok(RicCall::CreateVms)) => {
            let query = format!("
INSERT INTO Vms VALUES ('i-{:08}', 'small');
", req_id);
            connection.execute(query).unwrap();
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

    let connection = sqlite::Connection::open_with_full_mutex(":memory:").unwrap();
    let connection = Arc::new(connection);
    let requet_id = Arc::new(AtomicUsize::new(0));
    let query = "
    CREATE TABLE Vms (Id TEXT, VmType TEXT);
";
    connection.execute(query).unwrap();
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
