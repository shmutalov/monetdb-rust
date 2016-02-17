extern crate crypto;

use self::crypto::digest::Digest;
use self::crypto::md5::Md5;
use self::crypto::sha1::Sha1;
use self::crypto::sha2::{Sha256, Sha384, Sha512};

use protocol::{IMapiProtocol, Result};

/// Mapi protocol version 9
pub struct MapiProtocol9;

impl IMapiProtocol for MapiProtocol9 {
    fn build_challenge_response(&self, 
                                user_name: &str,
                                password: &str,
                                language: &str,
                                challenge_tokens: &Vec<&str>,
                                database: Option<&str>,
                                hash: Option<&str>,
                                ) -> Result<String> {
        if challenge_tokens.len() < 6 {
            return Err("Not enough parameters for building challenge response".to_owned())
        }
        
        let salt = challenge_tokens[0];
        let server_type = challenge_tokens[1];
        
        let hashes: Vec<&str> = hash.unwrap_or(challenge_tokens[3]).split(",").collect();
        
        // get hashing algorithm
        let algorithm = challenge_tokens[5].to_uppercase();
        
        // create hasher
        let hasher: Box<Digest> = match algorithm.as_ref() {
            "MD5" => Box::new(Md5::new()),
            "SHA1" => Box::new(Sha1::new()),
            "SHA256" => Box::new(Sha256::new()),
            "SHA384" => Box::new(Sha384::new()),
            "SHA512" => Box::new(Sha512::new()),
            _ => return Err(format!("Hashing algorithm {} is not supported by this platform", algorithm))
        };
        
        hasher.input_str(password);
        let password_hash = hasher.result_str();
        
        // if server_type == "merovingian" && language != "control" {
        //     user_name_copy.push_str("merovingian");
        //     password_hash.push_str("merovingian");
        // }
        
        let mut found_algorithm = String::new();
        
        // found hash
        for h in hashes {
            match h {
                "MD5" | 
                "SHA1" | 
                "SHA256" | 
                "SHA384" | 
                "SHA512" => {
                    found_algorithm.push_str(h);
                    break;
                },
                _ => continue
            };
        }
        
        if found_algorithm.is_empty() {
            return Err("No supported hashing methods".to_owned());
        }
        
        // create hasher
        let second_hasher: Box<Digest> = match found_algorithm.as_ref() {
            "MD5" => Box::new(Md5::new()),
            "SHA1" => Box::new(Sha1::new()),
            "SHA256" => Box::new(Sha256::new()),
            "SHA384" => Box::new(Sha384::new()),
            "SHA512" => Box::new(Sha512::new()),
            _ => return Err(format!("Hashing algorithm {} is not supported by this platform", found_algorithm))
        };
        
        second_hasher.input_str(password_hash.as_ref());
        second_hasher.input_str(salt);
        
        let final_password_hash = second_hasher.result_str();
        
        let pwd_hash = format!("{{{0}}}{1}", found_algorithm, password_hash);
        
        let endianness = if cfg!(target_endian = "big") {
                            "BIG"
                        } else {
                            "LIT"
                        };
        
        let db = match database {
                    Some(name) => name,
                    None => ""  
                };
        
        let final_hash = format!("{0}:{1}:{2}:{3}:{4}:", 
            endianness, 
            user_name, 
            pwd_hash,
            language,
            db
            );
        
        return Ok(final_hash);
    }
}