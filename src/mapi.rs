extern crate url;
use self::url::Url;

use std::net::TcpStream;
use std::net::SocketAddr;
use std::io::{BufReader, BufWriter};

use protocol::{IMapiProtocol, Result, MapiProtocolFactory, MapiProtocolTypes};

pub struct MapiSocket {
    socket: TcpStream,
    from_database: BufReader<TcpStream>,
    to_database: BufWriter<TcpStream>,
}

impl MapiSocket {
    /// Connects to a given host.
    pub fn connect(&self,
        host: &str,
        port: u16,
        user_name: &str,
        password: &str,
        database: Option<&str>) -> Result<bool> {
            
        // set default port
        if port == 0 {
            port = 50000;
        }
        
        // set default database
        let db = match database {
            Some(name) => name,
            None => "monetdb"
        };
        
        // build address
        let addr: SocketAddr = (format!("{0}:{1}", host, port)).parse().unwrap();
        
        let socket = match TcpStream::connect(addr) {
            Ok(stream) => stream,
            Err(_) => return Err(format!("Unable to connect to the server '{}'", addr))
        };
        
        self.from_database = BufReader::new(socket);
        self.to_database = BufWriter::new(socket);
        
        // read challenge message
        let challenge = self.from_database.read_line().unwrap();
        
        // wait server
        self.from_database.read_line().unwrap();
        
        let response = match self.get_challenge_response(
            challenge, 
            user_name, 
            password, 
            "sql", 
            db, 
            None) {
                
            Ok(s) => s,
            Err(e) => return Err(e)
        };
            
        self.to_database.write_line(response);
        self.to_database.flush();
        
        let mut temp = match self.to_database.read_line() {
            Ok(s) => s,
            Err(e) => return Err(e)
        };
        
        let mut redirect_urls: Vec<&str> = vec![];
        let mut warnings: Vec<&str> = vec![];
        
        while temp != "." {
            if temp.is_empty() {
                return Err("Connection to the server was lost".to_owned())
            }
            
            match temp[0] {
                '!' => return Err(temp[1..]),
                '#' => warnings.push(temp[1..]),
                '^' => redirect_urls.push(temp[1..])
            }
            
            temp = match self.from_database.read_line() {
                Ok(s) => s,
                Err(e) => return Err(e)
            }
        }
        
        if redirect_urls.len() == 0 {
            return Ok(true);
        }
            
        self.socket.close();
            
        Ok(self.follow_redirects(&redirect_urls, user_name, password));
    }
    
    pub fn get_challenge_response(&self,
        challenge: &str,
        user_name: &str,
        password: &str,
        language: &str,
        database: &str,
        hash: Option<&str>) -> Result<String> {
        let tokens: Vec<&str> = challenge.split(":").collect();
        
        if tokens.len() <= 4 {
            return Err(format!("Server challenge unusable! Challenge contains too few tokens: {0}", challenge));
        }
        
        let version: u8 = match tokens[2].parse() {
            Ok(i) => i,
            Err(_) => return Err(format!("Unknown Mapi protocol '{0}'", tokens[2]))
        };
        
        let factory = MapiProtocolFactory;
        
        // get Mapi protocol instance
        let protocol: Box<IMapiProtocol> = match version {
            8 => factory.get(MapiProtocolTypes::Version8),
            9 => factory.get(MapiProtocolTypes::Version9),
            _ => return Err(format!("Unsupported protocol version '{0}'", version))
        };
        
        return Ok(protocol.build_challenge_response(user_name,
            password,
            language,
            tokens,
            database,
            hash,    
        ));
    }
    
    pub fn follow_redirects(&self,
        redirect_urls: &Vec<&str>,
        user_name: &str,
        password: &str) -> Result<bool> {
            
        let url = match Url::parse(redirect_urls[0]) {
            Ok(u) => u,
            Err(_) => return Err("Unknown redirection host".to_owned())
        };
        
        Ok(self.connect(url.host(), url.port(), user_name, password, url.query));
    }
        
    pub fn close(&self) {
        self.from_database.close();
        self.to_database.close();
        self.socket.close();
    }
}