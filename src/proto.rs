//! Protobuf message subsets, field numbers mirroring RustDesk's
//! hbb_common/protos/rendezvous.proto and base/protos/message.proto.
//! Wire-compatible subsets only — unknown fields on either side are
//! ignored/omitted per protobuf semantics.

// ---------------- rendezvous.proto ----------------

#[derive(Clone, PartialEq, prost::Message)]
pub struct PunchHoleRequest {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(int32, tag = "2")]
    pub nat_type: i32,
    #[prost(string, tag = "3")]
    pub licence_key: String,
    #[prost(int32, tag = "4")]
    pub conn_type: i32, // ConnType: 2 = PORT_FORWARD
    #[prost(string, tag = "5")]
    pub token: String,
    #[prost(string, tag = "6")]
    pub version: String,
    #[prost(int32, tag = "7")]
    pub udp_port: i32,
    #[prost(bool, tag = "8")]
    pub force_relay: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PunchHoleResponse {
    #[prost(bytes, tag = "1")]
    pub socket_addr: Vec<u8>, // AddrMangle-encoded
    #[prost(bytes, tag = "2")]
    pub pk: Vec<u8>, // server-signed IdPk blob
    #[prost(int32, tag = "3")]
    pub failure: i32,
    #[prost(string, tag = "4")]
    pub relay_server: String,
    #[prost(oneof = "punch_hole_response::Union", tags = "5, 6")]
    pub union: Option<punch_hole_response::Union>,
}

pub mod punch_hole_response {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Union {
        #[prost(int32, tag = "5")]
        NatType(i32),
        #[prost(bool, tag = "6")]
        IsLocal(bool),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RequestRelay {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub uuid: String,
    #[prost(bytes, tag = "3")]
    pub socket_addr: Vec<u8>,
    #[prost(string, tag = "4")]
    pub relay_server: String,
    #[prost(bool, tag = "5")]
    pub secure: bool,
    #[prost(string, tag = "6")]
    pub licence_key: String,
    #[prost(int32, tag = "7")]
    pub conn_type: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RelayResponse {
    #[prost(bytes, tag = "1")]
    pub socket_addr: Vec<u8>,
    #[prost(string, tag = "2")]
    pub uuid: String,
    #[prost(string, tag = "3")]
    pub relay_server: String,
    #[prost(string, tag = "6")]
    pub refuse_reason: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RendezvousMessage {
    #[prost(oneof = "rendezvous_message::Union", tags = "8, 9, 10, 11, 12, 13, 18, 19")]
    pub union: Option<rendezvous_message::Union>,
}

pub mod rendezvous_message {
    use super::*;

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Union {
        #[prost(message, tag = "8")]
        PunchHoleRequest(PunchHoleRequest),
        #[prost(message, tag = "9")]
        PunchHole(super::PunchHole),
        #[prost(message, tag = "10")]
        PunchHoleSent(super::PunchHoleSent),
        #[prost(message, tag = "11")]
        PunchHoleResponse(PunchHoleResponse),
        #[prost(message, tag = "12")]
        FetchLocalAddr(super::FetchLocalAddr),
        #[prost(message, tag = "13")]
        LocalAddr(super::LocalAddr),
        #[prost(message, tag = "18")]
        RequestRelay(RequestRelay),
        #[prost(message, tag = "19")]
        RelayResponse(RelayResponse),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PunchHole {
    #[prost(bytes, tag = "1")]
    pub socket_addr: Vec<u8>,
    #[prost(string, tag = "2")]
    pub relay_server: String,
    #[prost(int32, tag = "3")]
    pub nat_type: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PunchHoleSent {
    #[prost(bytes, tag = "1")]
    pub socket_addr: Vec<u8>,
    #[prost(string, tag = "2")]
    pub id: String,
    #[prost(string, tag = "3")]
    pub relay_server: String,
    #[prost(int32, tag = "4")]
    pub nat_type: i32,
    #[prost(string, tag = "5")]
    pub version: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct FetchLocalAddr {
    #[prost(bytes, tag = "1")]
    pub socket_addr: Vec<u8>,
    #[prost(string, tag = "2")]
    pub relay_server: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct LocalAddr {
    #[prost(bytes, tag = "1")]
    pub socket_addr: Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub local_addr: Vec<u8>,
    #[prost(string, tag = "3")]
    pub relay_server: String,
    #[prost(string, tag = "4")]
    pub id: String,
    #[prost(string, tag = "5")]
    pub version: String,
}

// ---------------- message.proto (session) ----------------

#[derive(Clone, PartialEq, prost::Message)]
pub struct IdPk {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(bytes, tag = "2")]
    pub pk: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub kx_version: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignedId {
    #[prost(bytes, tag = "1")]
    pub id: Vec<u8>, // sign::sign(IdPk)
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PublicKey {
    #[prost(bytes, tag = "1")]
    pub asymmetric_value: Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub symmetric_value: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub kx_version: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Hash {
    #[prost(string, tag = "1")]
    pub salt: String,
    #[prost(string, tag = "2")]
    pub challenge: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PortForward {
    #[prost(string, tag = "1")]
    pub host: String,
    #[prost(int32, tag = "2")]
    pub port: i32,
    #[prost(bool, tag = "3")]
    pub multiplex: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct LoginRequest {
    #[prost(string, tag = "1")]
    pub username: String,
    #[prost(bytes, tag = "2")]
    pub password: Vec<u8>, // sha256(sha256(pw + salt) + challenge)
    #[prost(string, tag = "4")]
    pub my_id: String,
    #[prost(string, tag = "5")]
    pub my_name: String,
    #[prost(uint64, tag = "10")]
    pub session_id: u64,
    #[prost(string, tag = "11")]
    pub version: String,
    #[prost(string, tag = "13")]
    pub my_platform: String,
    #[prost(oneof = "login_request::Union", tags = "7, 8")]
    pub union: Option<login_request::Union>,
}

pub mod login_request {
    use super::*;

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Union {
        #[prost(message, tag = "7")]
        FileTransfer(FileTransfer),
        #[prost(message, tag = "8")]
        PortForward(PortForward),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct FileTransfer {
    #[prost(string, tag = "1")]
    pub dir: String,
    #[prost(bool, tag = "2")]
    pub show_hidden: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PeerInfo {
    #[prost(string, tag = "1")]
    pub username: String,
    #[prost(string, tag = "2")]
    pub hostname: String,
    #[prost(string, tag = "3")]
    pub platform: String,
    #[prost(string, tag = "7")]
    pub version: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct LoginResponse {
    #[prost(oneof = "login_response::Union", tags = "1, 2")]
    pub union: Option<login_response::Union>,
}

pub mod login_response {
    use super::*;

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Union {
        #[prost(string, tag = "1")]
        Error(String),
        #[prost(message, tag = "2")]
        PeerInfo(PeerInfo),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PortForwardOpen {
    #[prost(int32, tag = "1")]
    pub channel_id: i32,
    #[prost(string, tag = "2")]
    pub host: String,
    #[prost(int32, tag = "3")]
    pub port: i32,
    #[prost(uint32, tag = "4")]
    pub window: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PortForwardOpened {
    #[prost(int32, tag = "1")]
    pub channel_id: i32,
    #[prost(bool, tag = "2")]
    pub success: bool,
    #[prost(string, tag = "3")]
    pub message: String,
    #[prost(uint32, tag = "4")]
    pub window: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PortForwardData {
    #[prost(int32, tag = "1")]
    pub channel_id: i32,
    #[prost(bytes, tag = "2")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PortForwardClose {
    #[prost(int32, tag = "1")]
    pub channel_id: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PortForwardWindowUpdate {
    #[prost(int32, tag = "1")]
    pub channel_id: i32,
    #[prost(uint32, tag = "2")]
    pub add: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PortForwardChannel {
    #[prost(oneof = "port_forward_channel::Union", tags = "1, 2, 3, 4, 5")]
    pub union: Option<port_forward_channel::Union>,
}

pub mod port_forward_channel {
    use super::*;

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Union {
        #[prost(message, tag = "1")]
        Open(PortForwardOpen),
        #[prost(message, tag = "2")]
        Opened(PortForwardOpened),
        #[prost(message, tag = "3")]
        Data(PortForwardData),
        #[prost(message, tag = "4")]
        Close(PortForwardClose),
        #[prost(message, tag = "5")]
        WindowUpdate(PortForwardWindowUpdate),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Misc {
    #[prost(string, tag = "9")]
    pub close_reason: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Message {
    #[prost(oneof = "message::Union", tags = "3, 4, 7, 8, 9, 19, 33")]
    pub union: Option<message::Union>,
}

pub mod message {
    use super::*;

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Union {
        #[prost(message, tag = "3")]
        SignedId(SignedId),
        #[prost(message, tag = "4")]
        PublicKey(PublicKey),
        #[prost(message, tag = "7")]
        LoginRequest(LoginRequest),
        #[prost(message, tag = "8")]
        LoginResponse(LoginResponse),
        #[prost(message, tag = "9")]
        Hash(Hash),
        #[prost(message, tag = "19")]
        Misc(Misc),
        #[prost(message, tag = "33")]
        PortForwardChannel(PortForwardChannel),
    }
}
