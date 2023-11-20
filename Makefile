SHELL = /bin/bash
PCAP_FN:=/storage/pcaps/captured_lab_traffic_sample.pcap

benchmark-lpa:
	time large_pcap_analyzer -p $(PCAP_FN)

benchmark-rust:
	cargo build --release 2>/dev/null
	time target/release/rust-pcap-analyzer $(PCAP_FN)

benchmarks:
	$(MAKE) -s benchmark-lpa
	$(MAKE) -s benchmark-rust

check-for-unsafe:
	# see https://github.com/rust-secure-code/cargo-geiger
	cargo geiger
