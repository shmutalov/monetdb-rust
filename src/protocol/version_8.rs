use protocol::{IMapiProtocol, Result};

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
        Err("Protocol not implemented yet".to_owned())
    }
}