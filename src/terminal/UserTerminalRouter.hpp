#ifndef __ET_USER_TERMINAL_ROUTER__
#define __ET_USER_TERMINAL_ROUTER__

#include <chrono>
#include <optional>

#include "Headers.hpp"
#include "PipeSocketHandler.hpp"
#include "ServerConnection.hpp"

namespace et {

class UserTerminalRouter {
 public:
  UserTerminalRouter(shared_ptr<PipeSocketHandler> _socketHandler,
                     const SocketEndpoint& _routerEndpoint);
  inline int getServerFd() { return serverFd; }
  /** @brief Advances bounded, nonblocking registration reads. Call each tick;
   * returns one completed registration or an empty pair. */
  IdKeyPair acceptNewConnection();
  /** @brief Returns the pending read set after a change, updating generation.
   * Refresh these descriptors in the poller even if numbers were reused. */
  std::optional<set<int>> pendingRegistrationFds(uint64_t& generation) const;

  std::optional<TerminalUserInfo> tryGetInfoForConnection(
      const shared_ptr<ServerClientConnection>& serverClientState);

  inline shared_ptr<PipeSocketHandler> getSocketHandler() {
    return socketHandler;
  }

 protected:
  struct PendingRegistration {
    string bytes;
    int64_t length = -1;
    std::chrono::steady_clock::time_point started =
        std::chrono::steady_clock::now();
  };
  static constexpr size_t MAX_PENDING_REGISTRATIONS = 64;
  static constexpr int64_t MAX_REGISTRATION_LENGTH = 4096;
  static constexpr std::chrono::seconds REGISTRATION_TIMEOUT{30};
  unordered_map<int, PendingRegistration> pendingRegistrations;
  uint64_t pendingFdsGeneration = 0;
  IdKeyPair registerTerminal(int terminalFd, const Packet& packet);
  int serverFd;
  unordered_map<string, TerminalUserInfo> idInfoMap;
  shared_ptr<PipeSocketHandler> socketHandler;
  mutable recursive_mutex routerMutex;
};
}  // namespace et

#endif  // __ET_ID_PASSKEY_ROUTER__
