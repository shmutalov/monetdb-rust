use std::io::TcpStream;
use std::io::net::ip::SocketAddr;
use std::io::{Writer, Buffer, BufferedStream};

use protocol::{IMapiProtocol, Result};

pub struct MapiSocket {
    socket: mut TcpStream,
    db_stream: mut BufferedStream,
};

impl MapiSocket {
    /// Connects to a given host.
    pub fn connect(&self,
                    host: String,
                    port: u16,
                    user_name: String,
                    password: String,
                    database: Option<String>
                    ) -> Result<bool> {
        // set default port
        if port == 0 {
            port = 50000;
        }
        
        // set default database
        let db = match database {
            Some(name) => name,
            None => "monetdb"
        }
        
        // build address
        let addr: SocketAddr = from_str(format!("{0}:{1}", host, port)).unwrap();
        
        let socket = match TcpStream::connect(addr) {
            Ok(stream) => stream,
            Err(_) => return Err(format!("Unable to connect to the server '{}'", addr))
        }         
        
        db_stream = BufferedStream::new(stream);
        
        // read challenge message
        let challenge = db_stream.read_line().unwrap();
        
        Ok(true);
    }
    
    pub fn close(&self);
}