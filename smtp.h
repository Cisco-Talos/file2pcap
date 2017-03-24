
int smtpRequest(struct handover *ho);
//char *base64_encode(char *data, size_t input_length, size_t *output_length);
int smtpTransferFile(struct handover *ho);
int transferFileUU(struct handover *ho);

