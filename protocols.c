#include <stdint.h>

#include "protocols.h"

void flip_16(uint16_t *p) {
  uint8_t *v = (uint8_t *) p;
  uint8_t tmp = v[0];
  v[0] = v[1];
  v[1] = tmp;
}

void endianfix_ether(struct header_ether *hd) {
  flip_16(&hd->type);
}

void endianfix_ip(struct header_ip *hd) {
  flip_16(&hd->length);
  flip_16(&hd->id);
  flip_16(&hd->flags_fragment_offset);
  flip_16(&hd->checksum);
}

void endianfix_udp(struct header_udp *hd) {
  flip_16(&hd->source_port);
  flip_16(&hd->dest_port);
  flip_16(&hd->length);
  flip_16(&hd->checksum);
}
