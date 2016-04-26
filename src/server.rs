// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use protobuf::{Message,ProtobufResult,RepeatedField,parse_from_reader};
use protocol::{
    ClientRequest,
    CacheStats,
    CacheStatistic,
    ServerResponse,
    ShuttingDown,
    UnknownCommand,
};
use std::io;
use std::net::{Shutdown,TcpListener, TcpStream};
use std::thread;


fn generate_stats() -> CacheStats {
    //TODO: actually populate this with real data
    let mut stats = CacheStats::new();
    let mut s1 = CacheStatistic::new();
    s1.set_name("stat 1".to_owned());
    s1.set_count(1000);
    let mut s2 = CacheStatistic::new();
    s2.set_name("stat 2".to_owned());
    s2.set_str("some/value".to_owned());
    let mut s3 = CacheStatistic::new();
    s3.set_name("stat 3".to_owned());
    s3.set_size(1024 * 1024 * 1024 * 3);
    stats.set_stats(RepeatedField::from_vec(vec!(s1, s2, s3)));
    stats
}

/// Handle a request from a client.
fn handle_client(mut stream: TcpStream) -> ProtobufResult<()> {
    println!("handle_client");
    match parse_from_reader::<ClientRequest>(&mut stream) {
        Ok(req) => {
            println!("handle_client: parsed request");
            let mut res = ServerResponse::new();
            if req.has_get_stats() {
                println!("handle_client: get_stats");
                res.set_stats(generate_stats());
            } else if req.has_shutdown() {
                println!("handle_client: shutdown");
                //TODO: actually handle this
                let mut shutting_down = ShuttingDown::new();
                shutting_down.set_stats(generate_stats());
                res.set_shuttingdown(shutting_down);
            } else {
                println!("handle_client: unknown command");
                res.set_unknown(UnknownCommand::new());
            }
            try!(res.write_to_writer(&mut stream));
            //TODO: propogate error
            stream.shutdown(Shutdown::Write).unwrap();
            Ok(())
        }
        Err(e) => {
            println!("handle_client: error parsing request: {}", e);
            Err(e)
        }
    }
}

/// Start an sccache server, listening on `port`.
pub fn start_server(port : u16) -> io::Result<()> {
    println!("start_server");
    let listener = try!(TcpListener::bind(("127.0.0.1", port)));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("start_server: got client");
                thread::spawn(move|| {
                    handle_client(stream).map_err(|e| {
                        println!("handle_client failed: {}", e);
                    })
                });
            }
            Err(_) => { /* connection failed */ }
        }
    }
    Ok(())
}
