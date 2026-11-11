#ifndef __ET_SOCKET_HANDLER__
#define __ET_SOCKET_HANDLER__

#include "Headers.hpp"
#include "Packet.hpp"

namespace et {
class SocketHandler {
 public:
  virtual ~SocketHandler() {}

  virtual bool hasData(int fd) = 0;
  virtual ssize_t read(int fd, void* buf, size_t count) = 0;
  virtual ssize_t write(int fd, const void* buf, size_t count) = 0;

  /** @brief Idle-gap timeout (seconds) used when `readAll(..., true)`. */
  static constexpr int SOCKET_IDLE_TIMEOUT_SEC = 30;
  /**
   * @brief Absolute read deadline (seconds) used when `readAll(..., true)`.
   * Unlike the idle timeout, this is not reset when bytes arrive.
   */
  static constexpr int SOCKET_ABSOLUTE_TIMEOUT_SEC = 60;

  /**
   * @brief Reads exactly `count` bytes, retrying on EAGAIN until the buffer
   * fills.
   * @param timeout Whether to enforce idle + absolute transfer timeouts.
   */
  void readAll(int fd, void* buf, size_t count, bool timeout);
  /**
   * @brief Reads exactly `count` bytes with explicit deadlines.
   * @param idleTimeoutSec Max seconds without any progress; 0 disables.
   * @param absoluteTimeoutSec Max seconds for the whole read; 0 disables.
   */
  void readAll(int fd, void* buf, size_t count, int idleTimeoutSec,
               int absoluteTimeoutSec);
  /**
   * @brief Attempts to write the full buffer and returns -1 on timeout/failure.
   * @return Total bytes written or -1 when the socket deadlocks.
   */
  int writeAllOrReturn(int fd, const void* buf, size_t count);
  void writeAllOrThrow(int fd, const void* buf, size_t count, bool timeout);

  /** @brief Default max length for length-prefixed protobuf reads (128 MiB). */
  static constexpr int64_t DEFAULT_MAX_PROTO_LENGTH = 128 * 1024 * 1024;
  /**
   * @brief Max length for pre-authentication / handshake protos (4 KiB).
   *
   * ConnectRequest and SequenceHeader are tiny; a large declared length would
   * pin memory on a handler thread before any auth.
   */
  static constexpr int64_t MAX_HANDSHAKE_PROTO_LENGTH = 4 * 1024;

  /**
   * @brief Reads a length-prefixed protobuf from the socket.
   * @tparam T Protobuf message type.
   * @throws std::runtime_error on invalid length or parse failure.
   */
  template <typename T>
  inline T readProto(int fd, bool timeout) {
    return readProto<T>(fd, timeout, DEFAULT_MAX_PROTO_LENGTH);
  }

  /**
   * @brief Reads a length-prefixed protobuf, rejecting lengths above @p
   * maxLength.
   */
  template <typename T>
  inline T readProto(int fd, bool timeout, int64_t maxLength) {
    T t;
    int64_t length;
    readAll(fd, &length, sizeof(int64_t), timeout);
    if (length < 0 || length > maxLength) {
      // If the message is <= 0 or too big, assume this is a bad packet and
      // throw
      string s = string("Invalid size (<0 or >max): ") + to_string(length);
      throw std::runtime_error(s.c_str());
    }
    if (length == 0) {
      return t;
    }
    string s(length, '\0');
    readAll(fd, &s[0], length, timeout);
    if (!t.ParseFromString(s)) {
      throw std::runtime_error("Invalid proto");
    }
    return t;
  }

  template <typename T>
  inline void writeProto(int fd, const T& t, bool timeout) {
    string s;
    if (!t.SerializeToString(&s)) {
      STFATAL << "Serialization of " << t.GetTypeName() << " failed!";
    }
    int64_t length = s.length();
    if (length < 0 || length > 128 * 1024 * 1024) {
      STFATAL << "Invalid proto length: " << length << " For proto "
              << t.GetTypeName();
    }
    writeAllOrThrow(fd, &length, sizeof(int64_t), timeout);
    if (length > 0) {
      writeAllOrThrow(fd, &s[0], length, timeout);
    }
  }

  inline bool readPacket(int fd, Packet* packet) {
    int64_t length;
    readAll(fd, (char*)&length, sizeof(int64_t), false);
    if (length < 0 || length > 128 * 1024 * 1024) {
      // If the message is < 0 or too big, assume this is a bad packet and throw
      string s("Invalid size (<0 or >128 MB): ");
      s += std::to_string(length);
      throw std::runtime_error(s.c_str());
    }
    if (length == 0) {
      return false;
    }
    string s(length, '\0');
    readAll(fd, &s[0], length, false);
    *packet = Packet(s);
    return true;
  }

  inline void writePacket(int fd, const Packet& packet) {
    string s = packet.serialize();
    int64_t length = s.length();
    if (length < 0 || length > 128 * 1024 * 1024) {
      STFATAL << "Invalid message length: " << length;
    }
    writeAllOrThrow(fd, (const char*)&length, sizeof(int64_t), false);
    if (length) {
      writeAllOrThrow(fd, &s[0], length, false);
    }
  }

  void writeB64(int fd, const char* buf, size_t count);
  void readB64(int fd, char* buf, size_t count);
  void readB64EncodedLength(int fd, string* out, size_t encodedLength);

  virtual int connect(const SocketEndpoint& endpoint) = 0;
  virtual set<int> listen(const SocketEndpoint& endpoint) = 0;
  virtual set<int> getEndpointFds(const SocketEndpoint& endpoint) = 0;
  virtual int accept(int fd) = 0;
  virtual void stopListening(const SocketEndpoint& endpoint) = 0;
  virtual void close(int fd) = 0;
  virtual vector<int> getActiveSockets() = 0;

 protected:
};
}  // namespace et

#endif  // __ET_SOCKET_HANDLER__
