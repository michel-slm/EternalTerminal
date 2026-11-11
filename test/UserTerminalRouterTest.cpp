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

// Registers a fake terminal with the given credentials and returns its fd.
int registerFakeTerminal(shared_ptr<PipeSocketHandler> socketHandler,
                         UserTerminalRouter& router,
                         const SocketEndpoint& routerEndpoint, const string& id,
                         const string& passkey, IdKeyPair* accepted) {
  int fd = socketHandler->connect(routerEndpoint);
  REQUIRE(fd >= 0);
  TerminalUserInfo tui;
  tui.set_id(id);
  tui.set_passkey(passkey);
  socketHandler->writePacket(
      fd, Packet(TerminalPacketType::TERMINAL_USER_INFO, protoToString(tui)));
  *accepted = router.acceptNewConnection();
  return fd;
}
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

TEST_CASE("UserTerminalRouter rejects malformed registration packets",
          "[UserTerminalRouter]") {
  // Each malformed packet must cost only the offending connection.
  auto socketHandler = std::make_shared<PipeSocketHandler>();

  RouterEndpoint testEndpoint;
  SocketEndpoint routerEndpoint;
  routerEndpoint.set_name(testEndpoint.path);
  InspectableUserTerminalRouter router(socketHandler, routerEndpoint);

  // Zero-length packet: an 8-byte zero length prefix.
  int fdZero = socketHandler->connect(routerEndpoint);
  REQUIRE(fdZero >= 0);
  const int64_t zero = 0;
  socketHandler->writeAllOrThrow(fdZero, &zero, sizeof(zero), false);
  IdKeyPair accepted = router.acceptNewConnection();
  REQUIRE(accepted.id.empty());
  REQUIRE(accepted.key.empty());

  // Wrong packet header: valid framing, header is not TERMINAL_USER_INFO.
  int fdHeader = socketHandler->connect(routerEndpoint);
  REQUIRE(fdHeader >= 0);
  socketHandler->writePacket(
      fdHeader, Packet(TerminalPacketType::TERMINAL_BUFFER, "junk"));
  accepted = router.acceptNewConnection();
  REQUIRE(accepted.id.empty());
  REQUIRE(accepted.key.empty());

  // TERMINAL_USER_INFO-framed packet whose payload is not valid protobuf
  // ("junk" = field 13, wire type 2, length 117 with 2 bytes remaining).
  int fdProto = socketHandler->connect(routerEndpoint);
  REQUIRE(fdProto >= 0);
  socketHandler->writePacket(
      fdProto, Packet(TerminalPacketType::TERMINAL_USER_INFO, "junk"));
  accepted = router.acceptNewConnection();
  REQUIRE(accepted.id.empty());
  REQUIRE(accepted.key.empty());

  // The router still accepts a valid registration afterwards.
  int fdOk = registerFakeTerminal(socketHandler, router, routerEndpoint,
                                  "still-alive", string(32, 'k'), &accepted);
  REQUIRE(accepted.id == "still-alive");
  socketHandler->close(fdZero);
  socketHandler->close(fdHeader);
  socketHandler->close(fdProto);
  socketHandler->close(fdOk);
  testEndpoint.cleanup(socketHandler);
}

TEST_CASE("UserTerminalRouter rejects registrations with invalid credentials",
          "[UserTerminalRouter]") {
  auto socketHandler = std::make_shared<PipeSocketHandler>();

  RouterEndpoint testEndpoint;
  SocketEndpoint routerEndpoint;
  routerEndpoint.set_name(testEndpoint.path);
  InspectableUserTerminalRouter router(socketHandler, routerEndpoint);

  IdKeyPair accepted;
  int fdShort = registerFakeTerminal(socketHandler, router, routerEndpoint,
                                     "short-key", "short", &accepted);
  REQUIRE(accepted.id.empty());
  int fdLong = registerFakeTerminal(socketHandler, router, routerEndpoint,
                                    "long-key", string(33, 'k'), &accepted);
  REQUIRE(accepted.id.empty());
  int fdEmptyId = registerFakeTerminal(socketHandler, router, routerEndpoint,
                                       "", string(32, 'k'), &accepted);
  REQUIRE(accepted.id.empty());
  int fdOk = registerFakeTerminal(socketHandler, router, routerEndpoint,
                                  "valid", string(32, 'k'), &accepted);
  REQUIRE(accepted.id == "valid");

  socketHandler->close(fdShort);
  socketHandler->close(fdLong);
  socketHandler->close(fdEmptyId);
  socketHandler->close(fdOk);
  testEndpoint.cleanup(socketHandler);
}
#endif
