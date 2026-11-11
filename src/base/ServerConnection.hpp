#ifndef __ET_SERVER_CONNECTION__
#define __ET_SERVER_CONNECTION__

#include "Headers.hpp"
#include "ServerClientConnection.hpp"
#include "SocketHandler.hpp"

namespace et {
struct IdKeyPair {
  string id;
  string key;
};

class ServerConnection {
 public:
  /**
   * @brief Maximum connections queued for or inside clientHandler; further
   * connections are closed on arrival. A slot frees when clientHandler
   * returns; queued connections wait for a pool worker with no deadline.
   */
  static constexpr int MAX_PENDING_HANDSHAKES = 64;

  explicit ServerConnection(std::shared_ptr<SocketHandler> socketHandler,
                            const SocketEndpoint& _serverEndpoint);

  ~ServerConnection();

  inline bool clientKeyExists(const string& clientId) {
    lock_guard<std::recursive_mutex> guard(classMutex);
    return clientKeys.find(clientId) != clientKeys.end();
  }

  inline bool clientConnectionExists(const string& clientId) {
    lock_guard<std::recursive_mutex> guard(classMutex);
    return clientConnections.find(clientId) != clientConnections.end();
  }

  inline shared_ptr<SocketHandler> getSocketHandler() { return socketHandler; }

  bool acceptNewConnection(int fd);

  void shutdown();

  inline void addClientKey(const string& id, const string& passkey) {
    lock_guard<std::recursive_mutex> guard(classMutex);
    clientKeys[id] = passkey;
  }

  void clientHandler(int clientSocketFd);

  bool removeClient(const string& id);

  shared_ptr<ServerClientConnection> getClientConnection(
      const string& clientId) {
    lock_guard<std::recursive_mutex> guard(classMutex);
    auto it = clientConnections.find(clientId);
    if (it == clientConnections.end()) {
      STFATAL << "Error: Tried to get a client connection that doesn't exist";
    }
    return it->second;
  }

  virtual bool newClient(
      shared_ptr<ServerClientConnection> serverClientState) = 0;

 protected:
  /** @brief Connections currently inside clientHandler's handshake stage. */
  int pendingHandshakes = 0;
  void destroyPartialConnection(const string& clientId);

  shared_ptr<SocketHandler> socketHandler;
  SocketEndpoint serverEndpoint;
  std::unordered_map<string, string> clientKeys;
  std::unordered_map<string, shared_ptr<ServerClientConnection>>
      clientConnections;
  std::unique_ptr<ThreadPool> clientHandlerThreadPool;
  recursive_mutex classMutex;
  mutex connectMutex;
};
}  // namespace et

#endif  // __ET_SERVER_CONNECTION__
