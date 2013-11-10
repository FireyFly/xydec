
 X/Y UDP packet format
=======================

  The UDP packets come in two variants: "type A" and "type B" packets.  The
  overall traffic seems to start with type A packets and after a while switches
  to type B for most communication.


## Type A
  Type A packets begin with either `0xAFA1` or `0xA1AF` depending on the
  direction of the packet (client-to-server or server-to-client, respectively).
  The header for type A packets match the following structure.

    struct packet_a {
      u8  src; /* AF or A1 */
      u8  dst; /* ... */

      u8  op;  /* high nibble: bitfield?  low nibble: type of packet */
               /* type (i.e. low nibble) is 0, 1, 2 or occasionally 3 */
      u8  un8; /* unknown, often 00 */

      u8  un1; /* unknown, single-bit checksum of sorts? */
      u32 un2; /* unknown */

      u16 un3; /* unknown, always a small number. Surprisingly often same as type */
    }

  The structure of the rest of the packet depends on its `type` (`op & 0xF`).
  `type` 0 and 1 seem to be used for handshaking.  `type` 1 sometimes contain
  multiple length-prefixed encrypted payloads (length in plaintext).  `type` 2
  contains a payload encrypted with a stream cipher, and its first 4 (encrypted)
  bytes seem to be some sort of length (as a u32).  Doesn't seem to use either
  of the known LCGs (the "pkx encryption" LCG and the "general" LCG). `type` 3
  packets are always exactly 12 bytes long.


## Type B
  Type B packets contain a set of "blocks" concatenated together.  Each block
  starts with a magic number (u16) and contains its length somehow in its block
  header.

### 0xD0F5
  These appear sometimes (??) before the more interesting 0xD0EA blocks, and I'm
  guessing they contain some sort of checksum of the next block/message?

    struct packet_b_d0f5 {
      u16 magic;    /* 0xD0F5 */
      u16 un1;      /* unknown */
      u8  un2[40];  /* unknown */
    }

### 0xD0EA
  These blocks seem to be by far the most common.  Each block consists of a
  header, a number of "metadata entries" (`(type, length, data)` tuples), and a
  payload (often, but not always, encrypted).  PKX data from "show"ing pokémon
  in a trade is the payload of such a block, for instance.  The structure of a
  0xD0EA block is given below.

    struct packet_b_d0ea {
      /* Header */
      u16 magic; /* 0xD0EA */
      u8  un1;   /* unknown */

      u8  metadata_bitfield;  /* (seemingly) maps somewhat to what metadata is present */
                              /* 0f  metadata: 00 01    03 04     1111
                                 0b  metadata: 00 01       04     1011
                                 03  metadata:       02           0011
                                 00  metadata:                    0000 */

      u16 size;  /* length of payload */

      u8  src;   /* A1/AF */
      u8  dst;   /* ... */

      u8  op;    /* high nibble: bitfield?, low nibble: block type */
                 /*  #  metadata   payload   (# is type/low nibble)
                    -----------------------
                     0  0 1     4        0   handshake
                     1  0 1   3 4        ?  (sometimes has payload)  ⎫
                     2      2           >0  (DATA packet)            ⎬ main
                     3                   0                           ⎪ comm.
                     4                   0   ping/pong?              ⎭ */
      u8  un8;

      u8  un1;   /* "conversation ID"? sender ID? consistent for */
                 /* (sender,receiver) pairs */

      u8  flags1;
      u16 pack_id;  /* seems to increase between packets */

      u8  checksum[16];  /* checksum, maybe? */

      /* Metadata section */
      struct {
        u8  type;
        u8  length;
        u8  data[length];
      } metadata[?];  /* not sure how to tell precise length */

      /*  meta->type  desc
         -----------------
          00          ?                (data: u32)
          01          checksum/key?    (data: u8[16], sometimes only 00s)
          02          "part" counter, 00 for "last part".  Messages are split up
                      in chunks if they exceed a fixed size.  If multiple chunks
                      of the same thing are sent, data is  01, 02, ..., k, 00
                      for a message split in `k+1` chunks.  (data: u8)
          03          maybe checksum   (data: u16)
          04          ?                (data: u8, usually/always 00?) */

      /* Payload */
      u8  payload[size];
    }

