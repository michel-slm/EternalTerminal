// Backported from upstream test/unit_tests/BackedIOTest.cpp, which 6.2.11
// does not have.
#include <sys/socket.h>
#include <unistd.h>

#include <thread>

#include "ETerminal.pb.h"
#include "SocketHandler.hpp"
#include "TestHeaders.hpp"

using namespace et;

namespace {
// Minimal handler that reads and writes plain file descriptors.
class FdSocketHandler : public SocketHandler {
 public:
  bool hasData(int fd) override { return waitOnSocketData(fd); }
  ssize_t read(int fd, void* buf, size_t count) override {
    return ::read(fd, buf, count);
  }
  ssize_t write(int fd, const void* buf, size_t count) override {
    return ::write(fd, buf, count);
  }
  int connect(const SocketEndpoint&) override { return -1; }
  set<int> listen(const SocketEndpoint&) override { return {}; }
  set<int> getEndpointFds(const SocketEndpoint&) override { return {}; }
  int accept(int fd) override { return fd; }
  void stopListening(const SocketEndpoint&) override {}
  void close(int fd) override { ::close(fd); }
  vector<int> getActiveSockets() override { return {}; }
};
}  // namespace

TEST_CASE("SocketHandler readProto reassembles bodies across read chunks",
          "[SocketHandler]") {
  FdSocketHandler handler;
  int fds[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

  et::CatchupBuffer sent;
  sent.add_buffer(string(200 * 1024, 'x'));
  std::thread writer([&]() { handler.writeProto(fds[1], sent, true); });
  const auto received = handler.readProto<et::CatchupBuffer>(fds[0], true);
  writer.join();
  REQUIRE(received.buffer_size() == 1);
  REQUIRE(received.buffer(0) == sent.buffer(0));

  handler.close(fds[0]);
  handler.close(fds[1]);
}
