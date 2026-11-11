#ifndef __ET_UNIX_SOCKET_HANDLER__
#define __ET_UNIX_SOCKET_HANDLER__

#include "SocketHandler.hpp"

namespace et {
class UnixSocketHandler : public SocketHandler {
 public:
  UnixSocketHandler();
  virtual ~UnixSocketHandler() {}

  virtual bool waitForData(int fd, int64_t sec, int64_t usec);
  virtual bool hasData(int fd);
  virtual ssize_t read(int fd, void* buf, size_t count);
  virtual ssize_t write(int fd, const void* buf, size_t count);
  virtual int accept(int fd);
  /**
   * @brief Returns true if an accept() errno is a transient, per-connection
   * failure that must be reported to the caller rather than aborting the
   * server (EAGAIN/EWOULDBLOCK, ECONNABORTED, EINTR).
   */
  static bool isTransientAcceptError(int err);
  /** @brief True when accept(2) failed because descriptors or kernel memory
   * ran out (EMFILE/ENFILE/ENOMEM/ENOBUFS), which a peer can provoke. */
  static bool isResourceExhausted(int err);
  virtual void close(int fd);
  virtual vector<int> getActiveSockets();

 protected:
  void addToActiveSockets(int fd);
  virtual void initSocket(int fd);
  virtual void initServerSocket(int fd);
  void setBlocking(int sockFd, bool blocking);

  map<int, shared_ptr<recursive_mutex>> activeSocketMutexes;
  recursive_mutex globalMutex;
};
}  // namespace et

#endif  // __ET_UNIX_SOCKET_HANDLER__
