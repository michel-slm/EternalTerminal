#ifndef __ET_PACKET_H__
#define __ET_PACKET_H__

#include "CryptoHandler.hpp"
#include "Headers.hpp"

namespace et {
class Packet {
 public:
  Packet() : encrypted(false), header(255) {}
  Packet(uint8_t _header, const string& _payload)
      : encrypted(false), header(_header), payload(_payload) {}
  Packet(bool _encrypted, uint8_t _header, const string& _payload)
      : encrypted(_encrypted), header(_header), payload(_payload) {}
  explicit Packet(const string& serializedPacket) {
    if (serializedPacket.size() < HEADER_SIZE) {
      throw MalformedPacketError("Serialized packet shorter than its header");
    }
    encrypted = serializedPacket[0];
    header = serializedPacket[1];
    payload = serializedPacket.substr(HEADER_SIZE);
  }

  void decrypt(shared_ptr<CryptoHandler> cryptoHandler) {
    if (encrypted) {
      encrypted = false;
      payload = cryptoHandler->decrypt(payload);
    } else {
      // Peer-controlled framing: sever this connection, not the process.
      throw MalformedPacketError(
          "Received an unencrypted packet on an encrypted connection");
    }
  }

  void encrypt(shared_ptr<CryptoHandler> cryptoHandler) {
    if (encrypted) {
      STFATAL << "Tried to encrypt a packet that was already encrypted";
    } else {
      encrypted = true;
      payload = cryptoHandler->encrypt(payload);
    }
  }

  bool isEncrypted() const { return encrypted; }
  uint8_t getHeader() const { return header; }
  string getPayload() const { return payload; }

  ssize_t length() const { return HEADER_SIZE + payload.length(); }

  string serialize() const {
    string s = "00" + payload;
    s[0] = uint8_t(encrypted);
    s[1] = header;
    return s;
  }

  static const int HEADER_SIZE = 2;

 protected:
  bool encrypted;
  uint8_t header;

  string payload;
};
}  // namespace et

#endif
