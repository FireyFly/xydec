
/* structs & typedefs */
typedef uint8_t  mac_t[6];
typedef uint32_t ip_t;

struct header_ether {
  mac_t    dest;
  mac_t    source;
  uint16_t type;
} __attribute__((packed));

struct header_ip {
  uint8_t  version_ihl;
  uint8_t  dscp_ecn;
  uint16_t length;
  uint16_t id;
  uint16_t flags_fragment_offset;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t checksum;
  ip_t     source;
  ip_t     dest;
} __attribute__((packed));

struct header_udp {
  uint16_t source_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;
} __attribute__((packed));

/* functions */
void endianfix_ether(struct header_ether *);
void endianfix_ip(struct header_ip *);
void endianfix_udp(struct header_udp *);
