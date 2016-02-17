use std::result;

pub type Result<T> = result::Result<T, String>;

pub trait IMapiProtocol {
    fn build_challenge_response(&self, 
                                user_name: &str,
                                password: &str,
                                language: &str,
                                challenge_tokens: &Vec<&str>,
                                database: Option<&str>,
                                hash: Option<&str>,
                                ) -> Result<String>;
}

pub enum MapiProtocolTypes {
    Version8,
    Version9
}

mod version_8;
mod version_9;

pub use self::factory::MapiProtocolFactory;
pub mod factory;