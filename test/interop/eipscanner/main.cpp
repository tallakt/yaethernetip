// EIPScanner's side of test/ethernet_ip/eipscanner_test.exs, written against EIPScanner's
// documented API only: discovery, the Identity object, explicit requests, and exclusive owner and
// input only connections to the test's adapter, whose outputs come back as its inputs. It prints
// PASS or FAIL for each check, and exits without closing its last connection, so that the adapter
// has one to time out.
//
// Usage: eip_peer ADAPTER BROADCAST

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <cip/connectionManager/NetworkConnectionParams.h>
#include "ConnectionManager.h"
#include "DiscoveryManager.h"
#include "IdentityObject.h"
#include "MessageRouter.h"
#include "SessionInfo.h"
#include "utils/Buffer.h"
#include "utils/Logger.h"

using namespace eipScanner::cip;
using eipScanner::ConnectionManager;
using eipScanner::DiscoveryManager;
using eipScanner::IdentityObject;
using eipScanner::MessageRouter;
using eipScanner::SessionInfo;
using eipScanner::cip::connectionManager::ConnectionParameters;
using eipScanner::cip::connectionManager::NetworkConnectionParams;
using eipScanner::utils::Buffer;
using eipScanner::utils::Logger;
using eipScanner::utils::LogLevel;

static int failures = 0;

static void check(bool ok, const std::string &what) {
  std::cout << (ok ? "PASS " : "FAIL ") << what << std::endl;
  if (!ok) failures++;
}

static int status(const MessageRouterResponse &response) {
  return static_cast<int>(response.getGeneralStatusCode());
}

// The test's layout, OpENer's: configuration 151, outputs 150 (32 bytes, run/idle header), inputs
// 100 (32 bytes), input only heartbeat 152; point to point both ways, 20 ms. EIPScanner adds the
// sequence count and the header to the sizes given.
static ConnectionParameters connection(CipUsint output, CipUint o2tSize, bool header) {
  ConnectionParameters p;
  p.connectionPath = {0x20, 0x04, 0x24, 151, 0x2C, output, 0x2C, 100};
  p.o2tRealTimeFormat = header;
  p.originatorVendorId = 342;
  p.originatorSerialNumber = 0x12345;
  p.t2oNetworkConnectionParams |= NetworkConnectionParams::P2P;
  p.t2oNetworkConnectionParams |= NetworkConnectionParams::SCHEDULED_PRIORITY;
  p.t2oNetworkConnectionParams |= 32;
  p.o2tNetworkConnectionParams |= NetworkConnectionParams::P2P;
  p.o2tNetworkConnectionParams |= NetworkConnectionParams::SCHEDULED_PRIORITY;
  p.o2tNetworkConnectionParams |= o2tSize;
  p.o2tRPI = 20000;
  p.t2oRPI = 20000;
  p.transportTypeTrigger |= NetworkConnectionParams::CLASS1;
  return p;
}

// What a connection received: packets, and of those with all 32 bytes equal, the values seen
// and the last.
struct Received {
  int packets = 0;
  int uniform = 0;
  int last = 0;
  std::set<int> values;
};

static void listen(const std::weak_ptr<eipScanner::IOConnection> &io,
                   const std::shared_ptr<Received> &received, const std::string &name) {
  if (auto ptr = io.lock()) {
    ptr->setReceiveDataListener([received](auto, auto, auto data) {
      received->packets++;
      if (data.size() == 32 && data[0] != 0) {
        bool same = true;
        for (auto byte : data) same = same && byte == data[0];
        if (same) {
          received->uniform++;
          received->last = data[0];
          received->values.insert(data[0]);
        }
      }
    });
    ptr->setCloseListener([name]() { std::cout << "closed " << name << std::endl; });
  }
}

// Runs the connections for the time given, the outputs all `value` and counting up every 100 ms.
static int run(ConnectionManager &manager, const std::weak_ptr<eipScanner::IOConnection> &owner,
               int value, std::chrono::milliseconds time) {
  auto start = std::chrono::steady_clock::now();
  auto next = start;
  while (std::chrono::steady_clock::now() - start < time) {
    if (std::chrono::steady_clock::now() >= next) {
      value = value % 250 + 1;
      if (auto ptr = owner.lock()) ptr->setDataToSend(std::vector<uint8_t>(32, value));
      next += std::chrono::milliseconds(100);
    }
    manager.handleConnections(std::chrono::milliseconds(2));
  }
  return value;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    std::cerr << "usage: eip_peer ADAPTER BROADCAST" << std::endl;
    return 2;
  }
  std::string adapter = argv[1];
  std::string broadcast = argv[2];
  Logger::setLogLevel(LogLevel::INFO);

  // Discovery: ListIdentity by broadcast; the adapter answers within 2 s.
  DiscoveryManager discovery(broadcast, 0xAF12, std::chrono::seconds(3));
  bool found = false;
  for (auto &device : discovery.discover()) {
    auto name = device.identityObject.getProductName();
    std::cout << "found \"" << name << "\" at " << device.socketAddress.toString() << std::endl;
    found = found || (name == "yaethernetip peer" && device.identityObject.getVendorId() == 0xFFFF);
  }
  check(found, "ListIdentity by broadcast finds the adapter");

  auto si = std::make_shared<SessionInfo>(adapter, 0xAF12);

  IdentityObject identity(1, si);
  std::cout << "identity: vendor " << identity.getVendorId() << ", type " << identity.getDeviceType()
            << ", product " << identity.getProductCode() << ", revision "
            << identity.getRevision().toString() << ", status " << identity.getStatus()
            << ", serial " << identity.getSerialNumber() << ", name \""
            << identity.getProductName() << "\"" << std::endl;
  check(identity.getVendorId() == 0xFFFF && identity.getProductCode() == 77 &&
            identity.getProductName() == "yaethernetip peer",
        "IdentityObject reads the adapter's identity");

  MessageRouter router;
  auto vendor = router.sendRequest(si, ServiceCodes::GET_ATTRIBUTE_SINGLE, EPath(0x01, 1, 1));
  CipUint vendorId = 0;
  if (status(vendor) == 0) {
    Buffer buffer(vendor.getData());
    buffer >> vendorId;
  }
  check(vendorId == 0xFFFF, "Get_Attribute_Single reads the vendor id");

  auto set = router.sendRequest(si, ServiceCodes::SET_ATTRIBUTE_SINGLE, EPath(0x04, 150, 3),
                                std::vector<uint8_t>(32, 0x5A));
  auto get = router.sendRequest(si, ServiceCodes::GET_ATTRIBUTE_SINGLE, EPath(0x04, 150, 3));
  check(status(set) == 0 && status(get) == 0 && get.getData() == std::vector<uint8_t>(32, 0x5A),
        "Set_Attribute_Single then Get_Attribute_Single of output assembly 150");

  auto unknown = router.sendRequest(si, ServiceCodes::GET_ATTRIBUTE_SINGLE, EPath(0x04, 99, 3));
  std::cout << "assembly 99: status 0x" << std::hex << status(unknown) << std::dec << std::endl;
  check(status(unknown) == 0x05, "an unknown assembly is path destination unknown (0x05)");

  ConnectionManager manager;

  auto refused = manager.forwardOpen(si, connection(150, 10, true));
  check(refused.lock() == nullptr, "a Forward_Open of the wrong size is refused");

  auto owner = manager.forwardOpen(si, connection(150, 32, true));
  check(owner.lock() != nullptr, "Forward_Open of an exclusive owner, 150/100");
  auto ownerIn = std::make_shared<Received>();
  listen(owner, ownerIn, "exclusive owner");

  auto second = manager.forwardOpen(si, connection(150, 32, true));
  check(second.lock() == nullptr, "a second exclusive owner of 150 is refused");

  auto inputOnly = manager.forwardOpen(si, connection(152, 0, false));
  check(inputOnly.lock() != nullptr, "Forward_Open of input only, 152/100");
  auto inputIn = std::make_shared<Received>();
  listen(inputOnly, inputIn, "input only");

  auto set2 = router.sendRequest(si, ServiceCodes::SET_ATTRIBUTE_SINGLE, EPath(0x04, 150, 3),
                                 std::vector<uint8_t>(32, 0x5A));
  std::cout << "set 150 while owned: status 0x" << std::hex << status(set2) << std::dec << std::endl;
  check(status(set2) == 0x0C, "setting owned outputs is an object state conflict (0x0C)");

  int value = run(manager, owner, 0, std::chrono::seconds(5));
  // Values 1 to 50 were sent, 100 ms each; 0x5A is what Set_Attribute_Single left before.
  std::cout << "owner: " << ownerIn->packets << " packets, " << ownerIn->uniform << " echoes of "
            << ownerIn->values.size() << " values, last " << ownerIn->last << " of " << value
            << std::endl;
  std::cout << "input only: " << inputIn->packets << " packets, " << inputIn->values.size()
            << " values, last " << inputIn->last << std::endl;
  check(ownerIn->packets > 200 && ownerIn->packets < 300,
        "the owner gets inputs at the RPI (250 in 5 s)");
  check(ownerIn->values.size() >= 45 && value - ownerIn->last <= 2,
        "the outputs come back as inputs, each value, within 200 ms");
  check(inputIn->packets > 200 && inputIn->values == ownerIn->values,
        "input only gets the same inputs");

  manager.forwardClose(si, owner);
  manager.forwardClose(si, inputOnly);
  run(manager, owner, value, std::chrono::milliseconds(200));
  check(!manager.hasOpenConnections(), "Forward_Close closes both");

  auto again = manager.forwardOpen(si, connection(150, 32, true));
  check(again.lock() != nullptr, "the exclusive owner opens again after Forward_Close");
  auto againIn = std::make_shared<Received>();
  listen(again, againIn, "exclusive owner again");
  value = run(manager, again, value, std::chrono::seconds(1));
  check(againIn->packets > 25, "and gets inputs");

  std::cout << (failures ? "FAILED " : "ALL PASSED ") << failures << std::endl;
  std::cout << "leaving the last connection open, for the adapter to time out" << std::endl;
  std::_Exit(failures ? 1 : 0);
}
