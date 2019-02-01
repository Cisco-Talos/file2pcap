
int httpGetRequest(struct handover *ho);
int httpPostRequest(struct handover *ho);
int httpPostFinalBoundary(struct handover *ho);
int httpGetRequestAcknowledge(struct handover *ho);
int httpTransferFile(struct handover *ho);
int httpGzipTail(struct handover *ho);
int tcpSendHttpChunked(struct handover *ho, char *buffer, int length, char direction);
