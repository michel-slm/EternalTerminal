#ifndef __PORT_FORWARD_HANDLER_H__
#define __PORT_FORWARD_HANDLER_H__

#include "Connection.hpp"
#include "ETerminal.pb.h"
#include "ForwardDestinationHandler.hpp"
#include "ForwardSourceHandler.hpp"
#include "SocketHandler.hpp"

namespace et {
class PortForwardHandler {
 public:
  /**
   * @brief Constructs forwarding helpers for network and router sockets.
   * @param userid Session uid used for privilege-dropped UNIX socket ops
   *        ((uid_t)-1 to disable).
   * @param groupid Session gid used with @p userid.
   */
  explicit PortForwardHandler(shared_ptr<SocketHandler> _networkSocketHandler,
                              shared_ptr<SocketHandler> _pipeSocketHandler,
                              uid_t userid = static_cast<uid_t>(-1),
                              gid_t groupid = static_cast<gid_t>(-1));
  /** @brief Polls all handlers for new destination/data and sends
   * `PortForwardData`. */
  void update(vector<PortForwardDestinationRequest>* requests,
              vector<PortForwardData>* dataToSend);
  void handlePacket(const Packet& packet, shared_ptr<Connection> connection);
#ifndef WIN32
  PortForwardSourceResponse createSource(const PortForwardSourceRequest& pfsr,
                                         string* sourceName, uid_t userid,
                                         gid_t groupid);
#endif
  PortForwardDestinationResponse createDestination(
      const PortForwardDestinationRequest& pfdr);

  void closeSourceFd(int fd);
  void addSourceSocketId(int socketId, int sourceFd);
  void closeSourceSocketId(int socketId);
  void sendDataToSourceOnSocket(int socketId, const string& data);

 protected:
  shared_ptr<SocketHandler> networkSocketHandler;
  shared_ptr<SocketHandler> pipeSocketHandler;
  /** @brief Session uid for UNIX connect/listen; (uid_t)-1 disables drop. */
  uid_t sessionUid;
  /** @brief Session gid for UNIX connect/listen; (gid_t)-1 disables drop. */
  gid_t sessionGid;
  /** @brief Active destination handlers keyed by socket id. */
  unordered_map<int, shared_ptr<ForwardDestinationHandler>> destinationHandlers;

  vector<shared_ptr<ForwardSourceHandler>> sourceHandlers;
  unordered_map<int, shared_ptr<ForwardSourceHandler>> socketIdSourceHandlerMap;
};
}  // namespace et

#endif  // __PORT_FORWARD_HANDLER_H__
