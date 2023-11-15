pub mod pcap_file;
use pcap_file::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Not enough arguments");
        return;
    }

    let fname = &args[1];

    let mut pcapf: PcapFile = PcapFile::new();
    pcapf.read(fname);
}
