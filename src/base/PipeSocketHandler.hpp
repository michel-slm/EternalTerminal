#ifndef __ET_PIPE_SOCKET_HANDLER__
#define __ET_PIPE_SOCKET_HANDLER__

#include "UnixSocketHandler.hpp"

namespace et {
class PipeSocketHandler : public UnixSocketHandler {
 public:
  PipeSocketHandler();
  virtual ~PipeSocketHandler() {}

  virtual int connect(const SocketEndpoint& endpoint);
#ifndef WIN32
  /**
   * @brief Connects to a UNIX socket after dropping to @p uid/@p gid.
   */
  int connectAsUser(const SocketEndpoint& endpoint, uid_t uid, gid_t gid);
#endif
  /**
   * @brief Creates a listening UNIX socket and stores it internally.
   */
  virtual set<int> listen(const SocketEndpoint& endpoint);
#ifndef WIN32
  /**
   * @brief Creates a listening UNIX socket after dropping to @p uid/@p gid.
   */
  set<int> listenAsUser(const SocketEndpoint& endpoint, uid_t uid, gid_t gid);
#endif
  /**
   * @brief Returns the listening fds for a previously registered pipe.
   */
  virtual set<int> getEndpointFds(const SocketEndpoint& endpoint);
  virtual void stopListening(const SocketEndpoint& endpoint);

 protected:
  map<string, set<int>> pipeServerSockets;
};
}  // namespace et

#endif  // __ET_TCP_SOCKET_HANDLER__
