#include "CryptoHandler.hpp"
#include "TestHeaders.hpp"

using namespace et;

TEST_CASE("DoesEncryptDecrypt", "[CryptoHandler]") {
  string key = "12345678901234567890123456789012";
  shared_ptr<CryptoHandler> encryptHandler(new CryptoHandler(key, 0));
  shared_ptr<CryptoHandler> decryptHandler(new CryptoHandler(key, 0));
  string message = "ET Phone Home";
  string encryptedMessage = encryptHandler->encrypt(message);
  REQUIRE(message != encryptedMessage);
  string decryptedMessage = decryptHandler->decrypt(encryptedMessage);
  REQUIRE(message == decryptedMessage);
}

TEST_CASE("Constructor rejects wrong-length keys", "[CryptoHandler]") {
  REQUIRE_THROWS_AS(CryptoHandler("short", 0), std::runtime_error);
  REQUIRE_THROWS_AS(
      CryptoHandler(string(crypto_secretbox_KEYBYTES + 1, 'k'), 0),
      std::runtime_error);
  REQUIRE_NOTHROW(CryptoHandler("12345678901234567890123456789012", 0));
}
