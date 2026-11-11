#ifndef WIN32
#include "ETerminal.pb.h"
#include "PipeSocketHandler.hpp"
#include "TestHeaders.hpp"
#include "UserTerminalRouter.hpp"

using namespace et;

namespace {
struct RouterEndpoint {
  string directory;
  string path;

  RouterEndpoint() {
    string tmpPath = GetTempDirectory() + string("et_test_router_XXXXXXXX");
    directory = string(mkdtemp(&tmpPath[0]));
    path = directory + "/router_pipe";
  }

  void cleanup(const shared_ptr<PipeSocketHandler>& socketHandler) {
    SocketEndpoint endpoint;
    endpoint.set_name(path);
    socketHandler->stopListening(endpoint);
    ::unlink(path.c_str());
    FATAL_FAIL(::rmdir(directory.c_str()));
  }
};

class InspectableUserTerminalRouter : public UserTerminalRouter {
 public:
  using UserTerminalRouter::UserTerminalRouter;

  pair<int64_t, int64_t> registeredUidGid(const string& id) {
    lock_guard<recursive_mutex> guard(routerMutex);
    return {idInfoMap.at(id).uid(), idInfoMap.at(id).gid()};
  }
};
}  // namespace

TEST_CASE(
    "UserTerminalRouter overrides self-asserted uid/gid with peer "
    "credentials",
    "[UserTerminalRouter]") {
  auto socketHandler = std::make_shared<PipeSocketHandler>();

  RouterEndpoint testEndpoint;
  SocketEndpoint routerEndpoint;
  routerEndpoint.set_name(testEndpoint.path);
  InspectableUserTerminalRouter router(socketHandler, routerEndpoint);

  // Assert ids other than our own; the router must store the real ones.
  int terminalFd = socketHandler->connect(routerEndpoint);
  REQUIRE(terminalFd >= 0);
  TerminalUserInfo tui;
  tui.set_id("forged-uid-term");
  tui.set_passkey(string(32, 'k'));
  tui.set_uid(getuid() == 0 ? 1 : 0);
  tui.set_gid(getgid() == 0 ? 1 : 0);
  socketHandler->writePacket(
      terminalFd,
      Packet(TerminalPacketType::TERMINAL_USER_INFO, protoToString(tui)));

  IdKeyPair accepted = router.acceptNewConnection();
  REQUIRE(accepted.id == "forged-uid-term");
  const auto [storedUid, storedGid] =
      router.registeredUidGid("forged-uid-term");
  REQUIRE(storedUid == static_cast<int64_t>(getuid()));
  REQUIRE(storedGid == static_cast<int64_t>(getgid()));

  socketHandler->close(terminalFd);
  testEndpoint.cleanup(socketHandler);
}
#endif
