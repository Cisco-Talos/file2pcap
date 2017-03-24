
int http2ConnectionUpgrade(struct handover *ho);
int http2SwitchingProtocols();
int http2ClientMagic(struct handover *ho);
int http2Settings(struct handover *ho);
int http2ClientGetRequest(struct handover *ho);
int http2SettingsAck(struct handover *ho);
//int http2MagicGetRequest(struct handover *ho);
int http2Headers(struct handover *ho);
int http2TransferFile(struct handover *ho);
int http2DataStreamClose(struct handover *ho);
int http2GoAway(struct handover *ho);


