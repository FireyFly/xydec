/* typedefs/structs */
typedef struct {
  uint8_t un1;
  uint8_t un2;
  uint8_t un3;
} __attribute__((packed)) date_t;

struct pokemon_raw {
  uint32_t enc_key;
  uint16_t un1;
  uint16_t checksum;

  uint16_t block[4][28];
} __attribute__((packed));

struct pokemon {
  uint32_t enc_key;
  uint16_t un1;
  uint16_t checksum;

  struct {
    uint16_t id;
    uint16_t held;
    uint16_t ot;
    uint16_t ot_secret;

    uint32_t exp;
    uint8_t  ability;
    uint8_t  ability_no;

    uint16_t un1;
    uint32_t un2;

    uint8_t  nature;
    uint8_t  flags;

    struct {
      uint8_t hp;
      uint8_t atk;
      uint8_t def;
      uint8_t spe;
      uint8_t spa;
      uint8_t spd;
    } __attribute__((packed)) ev;

    uint8_t  un3;
    uint16_t un4;
    uint8_t  pokerus;
    uint32_t un5;
    uint32_t ribbons;

    uint32_t un6;
    uint32_t un7;
    uint32_t un8;
    uint32_t un9;
  } __attribute__((packed)) a;

  struct {
    uint16_t nickname[12];
    uint16_t un1;

    uint16_t moves[4];
    uint8_t  pp[4];
    uint8_t  pp_ups[4];
    uint16_t egg_moves[4];

    uint16_t un2;
    uint32_t iv_flags;
  } __attribute__((packed)) b;

  struct {
    uint16_t ot_name_trade[12];
    uint8_t  unknown[0x20];
  } __attribute__((packed)) c;

  struct {
    uint16_t ot_name[12];
    uint8_t  un1[9];
    date_t   date_egg;
    date_t   date_met;
    uint8_t  un2;
    uint16_t location_egg;
    uint16_t location_met;
    uint8_t  ball;
    uint8_t  encounter_level_flags;
    uint8_t  un3;
    uint8_t  ot_game;
    uint8_t  country;
    uint8_t  region;
    uint8_t  region_3ds;
    uint8_t  ot_language;
    uint32_t un4;
  } __attribute__((packed)) d;
};

/* functions */
struct pokemon *decode_pokemon(struct pokemon_raw *data);
