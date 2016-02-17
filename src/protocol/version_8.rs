extern crate crypto;

use self::crypto::digest::Digest;
use self::crypto::md5::Md5;
use self::crypto::sha1::Sha1;

use protocol::{IMapiProtocol, Result};

/// Mapi protocol version 8
pub struct MapiProtocol8;

impl IMapiProtocol for MapiProtocol8 {
    fn build_challenge_response(&self, 
                                user_name: &str,
                                password: &str,
                                language: &str,
                                challenge_tokens: &Vec<&str>,
                                database: Option<&str>,
                                hash: Option<&str>,
                                ) -> Result<String> {
        if challenge_tokens.len() < 5 {
            return Err("Not enough parameters for building challenge response".to_owned())
        }
        
        let salt = challenge_tokens[0];
        let server_type = challenge_tokens[1];
        
        let hashes: Vec<&str> = hash.unwrap_or(challenge_tokens[3]).split(",").collect();
        
        let mut user_name_copy = String::new();
        let mut password_hash = String::new(); 
        
        if server_type == "merovingian" && language != "control" {
            user_name_copy.push_str("merovingian");
            password_hash.push_str("merovingian");
        } else {
            user_name_copy.push_str(user_name);
            password_hash.push_str(password);
        }
        
        let mut found_algorithm = String::new();
        
        // found hash
        for h in hashes {
            match h {
                "MD5" | 
                "SHA1" | 
                "plain" => {
                    found_algorithm.push_str(h);
                    break;
                },
                _ => continue
            };
        }
        
        if found_algorithm.is_empty() {
            return Err("No supported hashing methods".to_owned());
        }
        
        let mut pwd_hash = String::new();
        
        if found_algorithm == "plain" {
            pwd_hash = format!("{{{0}}}{1}{2}", found_algorithm, password_hash, salt);
        } else {
            // create hasher
            let mut second_hasher: Box<Digest> = match found_algorithm.as_ref() {
                "MD5" => Box::new(Md5::new()),
                "SHA1" => Box::new(Sha1::new()),
                _ => return Err(format!("Hashing algorithm {} is not supported by this platform", found_algorithm))
            };
            
            second_hasher.input_str(password_hash.as_ref());
            second_hasher.input_str(salt);
            
            let final_password_hash = second_hasher.result_str();
        
            pwd_hash = format!("{{{0}}}{1}", found_algorithm, final_password_hash);
        }
        
        let db = match database {
                    Some(name) => name,
                    None => ""  
                };
        
        // In proto 8 byte-order of the blocks is always little endian
        let final_hash = format!("{0}:{1}:{2}:{3}:{4}:", 
            "LIT", 
            user_name_copy, 
            pwd_hash,
            language,
            db
            );
        
        return Ok(final_hash);
    }
}