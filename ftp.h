
int ftpCommandsStartActive(struct handover *ho);
int ftpCommandsStartPassive(struct handover *ho);

int ftpCommandsEnd(struct handover *ho);
int ftpTransferFile(struct handover *ho);

int ftpGetRequest(struct handover *ho);
int ftpRequestAcknowledge(struct handover *ho);
int ftpTransferFile(struct handover *ho);
