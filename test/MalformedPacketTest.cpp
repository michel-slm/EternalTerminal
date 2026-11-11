// Backported regression tests for malformed and unauthenticated session
// packets. Upstream keeps these in test/unit_tests/BackedIOTest.cpp, which
// relies on fixtures 6.2.11 does not have.

#include <sys/socket.h>

#include "BackedReader.hpp"
#include "CryptoHandler.hpp"
#include "ETerminal.pb.h"
#include "Packet.hpp"
#include "PipeSocketHandler.hpp"
#include "TestHeaders.hpp"

using namespace et;

namespace {
const string kKey = "12345678901234567890123456789012";
}

TEST_CASE("CryptoHandler rejects ciphertext shorter than the tag",
          "[MalformedPacket]") {
  CryptoHandler receiver(kKey, 0);
  REQUIRE_THROWS_AS(receiver.decrypt("short"), MalformedPacketError);
}

TEST_CASE("CryptoHandler keeps its nonce after rejecting a ciphertext",
          "[MalformedPacket]") {
  CryptoHandler sender(kKey, 0);
  CryptoHandler receiver(kKey, 0);
  const string first = sender.encrypt("first");
  const string second = sender.encrypt("second");

  string tampered = first;
  tampered.back() ^= 1;
  REQUIRE_THROWS_AS(receiver.decrypt(tampered), MalformedPacketError);
  REQUIRE(receiver.decrypt(first) == "first");
  REQUIRE(receiver.decrypt(second) == "second");
}

TEST_CASE("Packet rejects malformed serializations", "[MalformedPacket]") {
  REQUIRE_THROWS_AS(Packet(string("x")), MalformedPacketError);

  Packet plain(1, "payload");
  auto crypto = make_shared<CryptoHandler>(kKey, 0);
  REQUIRE_THROWS_AS(plain.decrypt(crypto), MalformedPacketError);
}

TEST_CASE("stringToProto rejects unparsable payloads", "[MalformedPacket]") {
  REQUIRE_THROWS_AS(stringToProto<TerminalUserInfo>("junk"),
                    MalformedPacketError);
}

TEST_CASE("BackedReader uncounts catchup after rejecting an entry",
          "[MalformedPacket]") {
  int fds[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
  auto handler = make_shared<PipeSocketHandler>();
  auto sender = make_shared<CryptoHandler>(kKey, 0);
  BackedReader reader(handler, make_shared<CryptoHandler>(kKey, 0), fds[0]);

  Packet first(1, "first");
  first.encrypt(sender);
  Packet second(2, "second");
  second.encrypt(sender);
  string tampered = first.serialize();
  tampered.back() ^= 1;

  reader.revive(fds[0], {tampered, second.serialize()});
  Packet out;
  REQUIRE_THROWS_AS(reader.read(&out), MalformedPacketError);
  REQUIRE(reader.getSequenceNumber() == 0);

  reader.revive(fds[0], {first.serialize(), second.serialize()});
  REQUIRE(reader.read(&out) == 1);
  REQUIRE(out.getPayload() == "first");
  REQUIRE(reader.read(&out) == 1);
  REQUIRE(out.getPayload() == "second");
  REQUIRE(reader.getSequenceNumber() == 2);

  ::close(fds[0]);
  ::close(fds[1]);
}
