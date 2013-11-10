
int is_printable(char ch);

void hexdump_line(void *p, int len, int width);
void hexdump_o(void *p, int len, int offset, int indent);
void hexdump(void *p, int len);
