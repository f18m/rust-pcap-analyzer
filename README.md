# About This Project

This is just a test project to try different packet-parsing frameworks written in Rust.

# Useful crates

* https://crates.io/crates/pnet_packet
* https://crates.io/crates/net-parser-rs
* https://crates.io/crates/snoopy

This test project is basically overlapping (partially) with:
* https://crates.io/crates/pcap-file  (better than https://crates.io/crates/rpcap or https://crates.io/crates/pcap-rs)
* https://github.com/rusticata/pcap-analyzer 


# Benchmark results

This project `rust-pcap-analyzer` is not a full rewrite of the C++-based [https://github.com/f18m/large-pcap-analyzer](large-pcap-analyzer), but still it
makes sense to benchmark the two, asking the `large-pcap-analyzer` to just carry out some basic packet parsing.
Here's the result against a 4.2GB PCAP file:

```
$ make benchmarks

make -s benchmark-lpa
0M packets (492601 packets) were loaded from PCAP.
Parsing stats: 0.00% GTPu with valid inner transport, 0.00% GTPu with valid inner IP, 100.00% with valid transport, 0.00% with valid IP, 0.00% invalid.

real    0m0.853s
user    0m0.191s
sys     0m0.660s
make -s benchmark-rust
Opened successfully /storage/pcaps/captured_lab_traffic_sample.pcap
The PCAP header is: PcapHeader { magic_number: 2712847316, version_major: 2, version_minor: 4, thiszone: 0, sigfigs: 0, snaplen: 262144, network: 1 }
PCAP processing completed after loading 492601 packets

real    0m0.888s
user    0m0.253s
sys     0m0.631s
```

This shows that Rust and C++ have basically the same identical processing speed and they are both I/O-bound actually.


# A word on my experience with Rust

I found this to be really on-spot: https://fasterthanli.me/articles/frustrated-its-not-you-its-rust

