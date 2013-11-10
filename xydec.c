#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "hexdump.h"
#include "pcap.h"
#include "pkx.h"
#include "protocols.h"

/*-- structs --------------------------------------------*/
struct packet_ninty_1 {
  uint8_t  src;
  uint8_t  dst;

  uint8_t  op;   /* Lower nibble: packet (chunk) type.  Upper nibble: bitfield? */
                 /*  #  sections   payload
                    -----------------------
                     0  0 1     4        0   handshake
                     1  0 1   3 4        ?  (sometimes has payload)  \
                     2      2           >0  (DATA packet)            | main
                     3                   0                           | comm.
                     4                   0  ping/pong?               / */
  uint8_t  un8;

  uint8_t  un1; /* split into nibbles? */

  uint32_t un2;
  uint16_t un3;
  uint32_t un4;
  uint8_t  un5;

  /* TODO */
} __attribute__((packed));

struct packet_ninty_2_section {
  uint8_t type;
  uint8_t length;
  uint8_t data[0];
} __attribute__((packed));

struct packet_ninty_2_header {
  uint16_t magic;
  uint8_t  un1;

  uint8_t  section_bitfield; /* (seemingly) maps somewhat to what sections are present. */
                             /* 0f  sections: 00 01    03 04     1111
                                0b  sections: 00 01       04     1011
                                03  sections:       02           0011
                                00  sections:                    0000 */

  uint16_t size; /* of payload, in octets */

  uint8_t  src;
  uint8_t  dst;

  uint8_t  op;   /* Lower nibble: packet (chunk) type.  Upper nibble: bitfield. */
                 /*  #  sections   payload
                    -----------------------
                     0  0 1     4        0   handshake
                     1  0 1   3 4        ?  (sometimes has payload)  \
                     2      2           >0  (DATA packet)            | main
                     3                   0                           | comm.
                     4                   0  ping/pong?               / */

  uint8_t  un8;

  uint8_t  from; /* conversation ID? sender ID? consistent for (sender,receiver) */
                 /* pair. optional?  00, CF, 7D, F4, D0, E8, D1 */

  uint8_t  flags1;
  uint16_t pack_id;

  uint8_t  checksumish[16];

  /* Repeated struct packet_ninty_2_section until terminator section */
  struct packet_ninty_2_section sections[0];

  /* uint8_t payload[size]; */

} __attribute__((packed));

struct packet_ninty_2_8e2 {
  uint16_t un1;
  uint16_t length;

//uint8_t  un2;
//uint8_t  un3;
//uint16_t un4;
  uint32_t un2;

  uint32_t un5; /* Note: actually a 4-byte struct */
  uint32_t un6;
  uint32_t un7;

  uint32_t un8;
  uint32_t sublength;

  /* `sublength` octets of data */
  uint8_t  data[0];
} __attribute__((packed));

void print_pokemon_string(uint16_t *str, int maxlen) {
  for (int i=0; i<maxlen && str[i] != 0; i++) {
    putchar(str[i]); /* TODO: proper charset lookup. */
  }
}

void dump_pokemon(struct pokemon *pkmn) {
  printf("enc_key: %04x  checksum: %02x\n",
         pkmn->enc_key, pkmn->checksum);

  /* A block */
  printf("\nA:\n");
  printf("  [%3d] {held: %2d} (OT: %04x (%04x))\n",
         pkmn->a.id, pkmn->a.held, pkmn->a.ot, pkmn->a.ot_secret);
  printf("  exp: %8d   ability: %02x %02x\n",
         pkmn->a.exp, pkmn->a.ability, pkmn->a.ability_no);
  printf("  nature: %d  flags: %02x\n",
         pkmn->a.nature, pkmn->a.flags);
  printf("  EV: %3d/%3d/%3d/%3d/%3d/%3d\n",
          pkmn->a.ev.hp,  pkmn->a.ev.atk, pkmn->a.ev.def,
          pkmn->a.ev.spa, pkmn->a.ev.spd, pkmn->a.ev.spe);
  printf("  rus? %02x   ribbons: %08x\n",
         pkmn->a.pokerus, pkmn->a.ribbons);

  /* B Block */
  printf("\nB:\n");
  printf("  nickname: '");
  print_pokemon_string(pkmn->b.nickname, 12);
  printf("'\n");

  printf("  moves:     %04x %04x %04x %04x\n",
         pkmn->b.moves[0], pkmn->b.moves[1], pkmn->b.moves[2], pkmn->b.moves[3]);
  printf("  pp:        %4d %4d %4d %4d\n",
         pkmn->b.pp[0], pkmn->b.pp[1], pkmn->b.pp[2], pkmn->b.pp[3]);
  printf("  pp_ups:    %4d %4d %4d %4d\n",
         pkmn->b.pp_ups[0], pkmn->b.pp_ups[1], pkmn->b.pp_ups[2], pkmn->b.pp_ups[3]);
  printf("  egg_moves: %04x %04x %04x %04x\n",
         pkmn->b.egg_moves[0], pkmn->b.egg_moves[1], pkmn->b.egg_moves[2], pkmn->b.egg_moves[3]);
  printf("  IV: %2d/%2d/%2d/%2d/%2d/%2d\n",
         (pkmn->b.iv_flags >>  0) & 0x1F,
         (pkmn->b.iv_flags >>  5) & 0x1F,
         (pkmn->b.iv_flags >> 10) & 0x1F,
         (pkmn->b.iv_flags >> 20) & 0x1F,
         (pkmn->b.iv_flags >> 25) & 0x1F,
         (pkmn->b.iv_flags >> 15) & 0x1F);
  printf("  is_egg? %c  is_nicknamed? %c\n",
         (pkmn->b.iv_flags >> 30)? 'Y' : 'N',
         (pkmn->b.iv_flags >> 31)? 'Y' : 'N');

  /* C block */
  printf("C:\n");
  printf("  OT name (if traded): '");
  print_pokemon_string(pkmn->c.ot_name_trade, 12);
  printf("'\n");

  /* D block */
  printf("D:\n");
  printf("  OT name: '");
  print_pokemon_string(pkmn->d.ot_name, 12);
  printf("'\n");

  printf("  date_egg: %2d %2d %2d   location_egg: %04x\n",
         pkmn->d.date_egg.un1, pkmn->d.date_egg.un2, pkmn->d.date_egg.un3,
         pkmn->d.location_egg);
  printf("  date_met: %2d %2d %2d   location_met: %04x\n",
         pkmn->d.date_met.un1, pkmn->d.date_met.un2, pkmn->d.date_met.un3,
         pkmn->d.location_met);
  printf("  ball: %02x  encounter_level: %d  OT gender: %c  OT game: %c\n",
         pkmn->d.ball, pkmn->d.encounter_level_flags & 0x7,
         pkmn->d.encounter_level_flags & 0x8? 'F' : 'M',
         pkmn->d.ot_game == 24? 'X' :
         pkmn->d.ot_game == 25? 'Y' : '?');
  printf("  OT country: %2d  OT region: %2d  OT 3DS region: %2d  OT lang: %2d\n",
         pkmn->d.country, pkmn->d.region, pkmn->d.region_3ds, pkmn->d.ot_language);
}

/* NOTE: "high-level" struct */
struct packet_ninty_2 {
  struct packet_ninty_2_header  *header;
  struct packet_ninty_2_section *sections;
  void                          *data;
  void                          *end;
};

struct packet_ninty_2 *parse_ninty_2(uint8_t *buf, uint8_t *buf_end) {
  struct packet_ninty_2_header *header = (void *) buf;

  /* Make sure that we actually have a type B chunk. */
  if (header->magic != 0xD0EA) return NULL;

  struct packet_ninty_2 *res = malloc(sizeof(struct packet_ninty_2));
  res->header   = header;
  res->sections = header->sections;

  struct packet_ninty_2_section *sec = header->sections,
                                *sec_;
  uint8_t *last = (void *) header->sections;
  while (sec < buf_end) {
    sec_ = sec;
    sec = (void *) ((uint8_t *) (sec + 1) + sec->length);

    /* end of sections */
    if (sec_->type == 0x02 || sec_->type == 0x04) break; /* TODO: difference? */

    /* TODO: hack: sometimes a chunk simply consists of no sections or payload
     * at all.  Therefore, it's necessary to check for new chunks even here. */
    if (sec_->type == 0xEA && sec_->length == 0xD0) {
      sec = sec_;
      break;
    }
  }

  /* Sanity check: Make sure we haven't exceeded the buffer boundary. */
  uint8_t *p = (void *) sec;
  assert(&p[header->size] <= buf_end);

  res->data = (void *) p;
  res->end  = (void *) (p + header->size);
  return res;
}


struct packet_ninty_3 {
  uint16_t magic;   /* 0xD0F5 */
  uint16_t un1;     /* zeroes */
  uint8_t  un2[40]; /* hash? */
} __attribute__((packed));


/*-- callback -------------------------------------------*/
int clamp(int n, int max) {
  return n > max? max : n;
}

#define CHECKSUM_COUNT 64
uint16_t checksums[CHECKSUM_COUNT];
uint8_t  checksum_idx = 0;

uint16_t ff_checksum_of(uint8_t *buf, int size) {
  union {
    uint8_t  u8[2];
    uint16_t u16;
  } __attribute__((packed)) res;
  res.u16 = 0;

  for (int i=0; i<size; i++) res.u8[i % 2] ^= buf[i];
  return res.u16;
}

void packet_callback(struct pcap_record_header *header, uint8_t *buf, int size) {
  /* Assume Ethernet, make sure that we have an IPv4 packet */
  struct header_ether *hd_ether = (void *) buf;
  endianfix_ether(hd_ether);

  if (hd_ether->type == 0x0806) { /* ARP */
    return;
  }

  if (hd_ether->type != 0x0800) { /* IPv4 */
//  printf("#### NOT IPv4! ####  (%04x)\n", hd_ether->type);
    return;
  }

  /* Have IPv4, check for UDP */
  struct header_ip *hd_ip = (void *) &buf[sizeof(struct header_ether)];
  endianfix_ip(hd_ip);

  assert(hd_ip->length == size - sizeof(struct header_ether));

  if (hd_ip->protocol == 6) { /* TCP */
  //printf("(skipping TCP packet)\n");
    return;
  }

  if (hd_ip->protocol != 17) { /* UDP */
//  printf("#### NOT UDP! ####  (%2d)\n", hd_ip->protocol);
    return;
  }

  int udp_base = sizeof(struct header_ether) + sizeof(struct header_ip);

  /* Have UDP, apply header & grab data */
  struct header_udp *hd_udp = (void *) &buf[udp_base];
  endianfix_udp(hd_udp);

  assert(hd_udp->length == size - udp_base);

  uint8_t *payload = (void *) &buf[udp_base + sizeof(struct header_udp)];
  int payload_len = hd_udp->length - sizeof(struct header_udp);
  uint8_t *payload_end = &payload[payload_len];

  /* Sanity check: packet ends after UDP payload? */
  assert(payload[payload_len    ] == 0xC4 &&
         payload[payload_len + 1] == 0xC4);

  uint16_t magic = *((uint16_t *) payload);

  /* FIXME: Temporary hacks/filters */
//if (hd_udp->length < 232) return;
//if (magic != 0xD0EA) return;  /* Only type B */
//if (magic != 0xA1AF && magic != 0xAFA1) return;  /* Only type A */
//if (hd_udp->length != 0x7F  &&
//    hd_udp->length != 0x12E &&
//    hd_udp->length != 0xFC  &&
//    hd_udp->length != 0x2E) return;

  if (hd_udp->source_port == 68 || hd_udp->dest_port == 68) return;  /* DHCP */
  if (hd_udp->source_port == 53 || hd_udp->dest_port == 53) return;  /* DNS */

  /* Check for duplicate packet */
  uint16_t csum = ff_checksum_of(payload, payload_len);
  printf("\033[38:5:242m[%04x]\033[m", csum);
  for (int i=0; i<CHECKSUM_COUNT; i++) {
    if (checksums[i] == csum) {
      printf("  \033[38:5:242m(repeated UDP payload)\033[m\n");
      putchar('\n');
      return;
    }
  }
  checksums[checksum_idx++] = csum;
  checksum_idx %= CHECKSUM_COUNT;

  /* Packet header (metadata) */
  printf("  {\033[1;38:5:%dm%08x\033[m:%04x} -> {\033[1;38:5:%dm%08x\033[m:%04x} [%3x] %d.%06d\n",
         2 + hd_ip->source % 11, hd_ip->source,  hd_udp->source_port,
         2 + hd_ip->dest   % 11, hd_ip->dest,    hd_udp->dest_port,
         payload_len, header->ts_sec, header->ts_usec);

  int last_chunk_known = 1;
  uint8_t *p = payload;
  do {
    magic = *((uint16_t *) p);

    struct packet_ninty_1 *nin_1;
    struct packet_ninty_2 *nin_2;
    struct packet_ninty_3 *nin_3;

    switch (magic) {
      case 0xA1AF: case 0xAFA1:
        nin_1 = (void *) p;

        int hl = (nin_1->op & 0xF) == 0;
        if (hl) printf("\033[1;31m");
        printf("Type A: %x (%x) %2x {%02x → %02x} %2x %4x %2x :: %8x %8x\n",
               nin_1->op >> 4, nin_1->op & 0xF, nin_1->un8,
               nin_1->src, nin_1->dst,
               nin_1->un1, nin_1->un3, nin_1->un5,
               nin_1->un2, payload_len >= 0x10? nin_1->un4 : -1);
            // x1h, x2h);
        if (hl) printf("\033[m");

        hexdump_o(payload, payload_len, 0, 4);
        putchar('\n');

        p = payload_end;
        return;

      case 0xD0F5:
        nin_3 = (void *) p;
        printf("Type C: %04x\n", nin_3->un1);
        p = p + sizeof(struct packet_ninty_3);
        break;

      case 0xD0EA:
        nin_2 = parse_ninty_2(p, payload_end);

        /* Chunk header metadata */
        printf("Type B: %x (%x) %2x [%3x]: {%02x} {%02x → %02x} %02x %4x %4x :: %2x\n",
               nin_2->header->op >> 4, nin_2->header->op & 0xF, nin_2->header->un8,
               nin_2->header->size,    nin_2->header->section_bitfield,
               nin_2->header->src,     nin_2->header->dst,
               nin_2->header->un1,
               nin_2->header->from,    nin_2->header->pack_id,
               nin_2->header->flags1);

        /* Look for 8E2 */
        if (nin_2->header->un8 == 0x08) {
          struct packet_ninty_2_8e2 *_8e2 = nin_2->data;

          if (_8e2->length == 0x10C) {
            struct pokemon *pkmn = decode_pokemon((void *) _8e2->data);

            printf("~~~~ trade ~~~\n");
            dump_pokemon(pkmn);
            putchar('\n');
            hexdump_o((uint8_t *) pkmn, _8e2->sublength, 0, 2);
            printf("~~~~ end   ~~~\n");
            putchar('\n');
          }
        }

        /* Chunk sections */
        struct packet_ninty_2_section *sec = nin_2->sections;
        while (sec < nin_2->data) {

          /*  sec->type  desc
             ---------------------------------
              00         beginning_of_message
              01         checksum/key?
              02         blob_1  {payload: "part" counter; 00 for "last part" }
                                  if multipart, sometimes starts counting later
                                  than 01 (why??)  [resent packets]
              03         maybe checksum
              04         blob_2 */

          printf("  sec: (%02x) [%02x]\n", sec->type, sec->length);
          hexdump_o(sec->data, sec->length, 0, 4);

          /* FIXME: fugly */
          sec = (void *) (((uint8_t *) &sec[1]) + sec->length);
        }

        /* Chunk payload */
        if (nin_2->header->size > 0) {
          printf("  payload:\n");
          hexdump_o(nin_2->data, nin_2->header->size, 0, 4);
        }

        /* Next chunk */
        p = nin_2->end;
        break;

      default:
        printf("[\033[1;31mUnidentified chunk\033[m]: %04x\n", magic);
        hexdump(p, clamp(payload_end - p, 0x100));
        putchar('\n');
        last_chunk_known = 0;
    }
  } while (last_chunk_known && p < payload_end);

//putchar('\n');
//hexdump(payload, clamp(payload_len, 0x100));
  putchar('\n');
}


/*-- main -----------------------------------------------*/
int main(void) {
  read_pcap(&packet_callback);
  return 0;
}
