#include <stdint.h>
#include <stdio.h>

#define SIZE 16

int is_printable(char ch) {
  return ch >= ' ' && ch <= '~';
}

void hexdump_line(uint8_t *buf, int len, int width) {
  uint8_t ch;

  /* Print hex part */
  for (int i=0; i<len; i++) {
    ch = buf[i];
    if (i % 8 == 0) putchar(' ');

         if (ch == 0)   printf("\033[38;5;238m");
    else if (ch <  ' ') printf("\033[38;5;150m");
    else if (ch >  '~') printf("\033[38;5;141m");

    printf(" %02x", ch);
    if (!is_printable(ch)) printf("\033[m");
  }

  /* Pad if not enough octets to fill a full line */
  for (int i=len; i < width; i++) {
    if (i % 8 == 0) putchar(' ');
    printf("   ");
  }

  putchar(' ');

  /* Print char part */
  for (int i=0; i<len; i++) {
    ch = buf[i];
    if (i % 8 == 0) putchar(' ');
    printf("%c", is_printable(ch)? ch : '.');
  }
}

void hexdump_o(void *p, int len, int offset, int indent) {
  uint8_t *buf = p;

  for (int i=0; i<len; i+=SIZE) {
    for (int j=0; j<indent; j++) putchar(' ');
    printf("%04x", offset + i);
    hexdump_line(&buf[offset + i], i > len - SIZE? len % SIZE : SIZE, SIZE);
    putchar('\n');
  }
}

void hexdump(void *p, int len) {
  hexdump_o(p, len, 0, 0);
}
