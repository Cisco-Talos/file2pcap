
char *quoted_printable_encode(int ch, size_t input_length, size_t *output_length);
int transferFileQuotedPrintable(struct handover *ho);
int encode(int ch, char *encoded_data);
void emit_literally(int ch, char *encoded_data);


