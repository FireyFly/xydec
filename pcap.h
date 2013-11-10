struct pcap_header {
  uint32_t magic;
  uint32_t version;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} __attribute__((packed));

struct pcap_record_header {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
} __attribute__((packed));

void read_pcap(void (*callback)(struct pcap_record_header *, uint8_t *, int len));
