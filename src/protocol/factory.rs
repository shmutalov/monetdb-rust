use protocol::{IMapiProtocol, MapiProtocolTypes};
use protocol::version_8::MapiProtocol8;
use protocol::version_9::MapiProtocol9;

pub struct MapiProtocolFactory;

impl MapiProtocolFactory {
    pub fn get(&self, proto: MapiProtocolTypes) -> Box<IMapiProtocol> {
        match proto {
            MapiProtocolTypes::Version8 => Box::new(MapiProtocol8),
            MapiProtocolTypes::Version9 => Box::new(MapiProtocol9),
        }
    }
}