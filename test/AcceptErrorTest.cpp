// Backported from upstream test/unit_tests/UnixSocketHandlerTest.cpp, which
// 6.2.11 does not have.
#include "TestHeaders.hpp"
#include "UnixSocketHandler.hpp"

using namespace et;

TEST_CASE("accept errors a peer can cause do not abort the server",
          "[AcceptError]") {
  // Transient, per-connection failures are retried.
  REQUIRE(UnixSocketHandler::isTransientAcceptError(EAGAIN));
  REQUIRE(UnixSocketHandler::isTransientAcceptError(EWOULDBLOCK));
  REQUIRE(UnixSocketHandler::isTransientAcceptError(ECONNABORTED));
  REQUIRE(UnixSocketHandler::isTransientAcceptError(EINTR));
  REQUIRE_FALSE(UnixSocketHandler::isTransientAcceptError(EBADF));

  // Exhaustion a peer can provoke is retried too; logic errors are not.
  REQUIRE(UnixSocketHandler::isResourceExhausted(EMFILE));
  REQUIRE(UnixSocketHandler::isResourceExhausted(ENFILE));
  REQUIRE(UnixSocketHandler::isResourceExhausted(ENOMEM));
  REQUIRE(UnixSocketHandler::isResourceExhausted(ENOBUFS));
  REQUIRE_FALSE(UnixSocketHandler::isResourceExhausted(EBADF));
}
