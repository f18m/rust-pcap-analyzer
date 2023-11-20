mod tests {
    #[test]
    fn pcap_file_read_non_existing() {
        let mut x = pcap_file::PcapFile::new();
        assert_eq!(x.read("/non/existing"), false);
    }
}
