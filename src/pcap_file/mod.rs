/*
 PcapFile
*/

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
#[repr(C, packed(1))]
struct PcapHeader {
    magic_number: u32,  /* magic number */
    version_major: u16, /* major version number */
    version_minor: u16, /* minor version number */
    thiszone: u32,      /* GMT to local correction */
    sigfigs: u32,       /* accuracy of timestamps */
    snaplen: u32,       /* max length of captured packets, in octets */
    network: u32,       /* data link type */
}

#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
#[repr(C, packed(1))]
struct PcaprecHdr {
    ts_sec: u32,   /* timestamp seconds */
    ts_usec: u32,  /* timestamp microseconds */
    incl_len: u32, /* number of octets of packet saved in file */
    orig_len: u32, /* actual length of packet */
}

pub struct PcapFile {
    actual_file: Option<File>,
    hdr: PcapHeader,
}

// IpAddr does not implement Default... so we cannot #[derive(Default)]
pub struct FlowInfo {
    ip_src: std::net::IpAddr,
    ip_dst: std::net::IpAddr,
    ip_proto: u8,
    port_src: u16,
    port_dst: u16,
    hash: u64,
}

impl Default for FlowInfo {
    fn default() -> Self {
        Self {
            ip_src: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            ip_dst: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            ip_proto: 0,
            port_src: 0,
            port_dst: 0,
            hash: 0,
        }
    }
}

enum PacketParsingError {
    NoIpLayer,
}

trait PacketParsing {
    fn parse(&self) -> Result<FlowInfo, PacketParsingError>;
}

#[derive(Default)]
pub struct PcapPacket {
    hdr: PcaprecHdr,
    body: Vec<u8>,
}

pub mod packet_parse;

impl PacketParsing for PcapPacket {
    fn parse(&self) -> Result<FlowInfo, PacketParsingError> {
        //format!("{}: {}", self.username, self.content)

        let epacket = pnet::packet::ethernet::EthernetPacket::new(&self.body).unwrap();
        packet_parse::handle_ethernet_frame(&epacket);

        return Err(PacketParsingError::NoIpLayer);
    }
}

impl PcapFile {
    pub fn new() -> PcapFile {
        PcapFile {
            actual_file: None,
            hdr: Default::default(),
        }
    }

    fn loop_packets(&mut self, reader: &mut std::io::BufReader<File>) -> Option<u32> {
        // now loop through the PCAP till we have packets to read:
        let mut p: PcapPacket = Default::default();
        let mut npkts = 0;
        loop {
            match bincode::deserialize_from(reader.by_ref()) {
                Err(e) => {
                    match e.as_ref() {
                        bincode::ErrorKind::Io(ioe) => {
                            if ioe.kind() == std::io::ErrorKind::UnexpectedEof {
                                // finished loading the whole PCAP file
                                break;
                            } else {
                                println!("Error during read of PCAP file: {}", ioe);
                                return None;
                            }
                        }
                        _ => {
                            println!(
                                "Error during deserialization of PCAP header2: {:?}",
                                e.as_ref()
                            );
                            return None;
                        }
                    }
                }

                Ok(h) => {
                    p.hdr = h;
                    //println!("The packet header is: {:?}", p.hdr);

                    // read the packet content
                    let expected_len: usize = p.hdr.incl_len.try_into().unwrap(); // safe: a uint32 will always fit a usize, RIGHT?????
                    p.body.resize(expected_len, 0);

                    reader.by_ref().read_exact(&mut p.body).unwrap(); // unsafe: panicking on IOerrors while reading
                }
            }

            // if we get here, the packet hdr&body have been read correctly
            _ = p.parse();
            npkts += 1;
        }

        Some(npkts)
    }

    pub fn read(&mut self, fname: &str) -> bool {
        let file_result = File::open(fname);
        match file_result {
            Err(e) => {
                println!("Error during open: {}", e);
                return false;
            }
            Ok(file) => {
                println!("Opened successfully {}", fname);

                let mut reader: std::io::BufReader<File> = std::io::BufReader::new(file);

                // read header
                match bincode::deserialize_from(&mut reader) {
                    Err(e) => {
                        println!("Error during deserialization of PCAP header1: {}", e);
                        return false;
                    }
                    Ok(h) => {
                        self.hdr = h;
                        println!("The PCAP header is: {:?}", self.hdr);
                    }
                }

                match self.loop_packets(&mut reader) {
                    Some(npkts) => {
                        // store the open file into the PcapFile "self" instance... by taking the ownership back from the BufReader
                        println!("PCAP processing completed after loading {npkts} packets");
                        self.actual_file = Some(reader.into_inner());
                    }
                    None => return false,
                }
            }
        }

        true
    }
}
