#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "pcap.h"

void read_pcap(void (*callback)(struct pcap_record_header *, uint8_t *, int len)) {
  uint8_t *p;

  /* Read pcap header */
  struct pcap_header header;

  p = (uint8_t *) &header;
  for (int i=0; i<24; i++) *p++ = getchar();

  assert(header.magic   == 0xa1b2c3d4);
  assert(header.network == 1); /* ethernet */

  /* Read packet records */
  uint8_t buf[header.snaplen];
  int     len;

  struct pcap_record_header rec_header;

  int ch; /* FIXME: hacky loop--probably shouldn't check for EOF this way */
  while ((ch = getchar()) != EOF) {
    ungetc(ch, stdin);

    for (int i=0; i<header.snaplen; i++) buf[i] = 0xC4; /* bad mem marker */

    p = (uint8_t *) &rec_header;
    for (int i=0; i<16; i++) *p++ = getchar();

    for (int i=0; i<rec_header.incl_len; i++) buf[i] = getchar();

    callback(&rec_header, &buf[0], rec_header.incl_len);
  }
}
