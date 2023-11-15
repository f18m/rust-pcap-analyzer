SHELL = /bin/bash
PCAP_FN:=/storage/pcaps/PROTOCOL_MIX_SCTP_M3UA_H248_BSSAP_GSMA_TCAP_MAP.pcap

benchmark-lpa:
	time large_pcap_analyzer -p $(PCAP_FN)

benchmark-rust:
	cargo build --release
	time target/release/rust-pcap-analyzer $(PCAP_FN)
