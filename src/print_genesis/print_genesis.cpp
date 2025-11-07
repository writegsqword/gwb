#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>

#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "serialization/serialization.h"
#include "serialization/binary_utils.h"

using namespace cryptonote;

// tiny hex helper
static std::string bytes_to_hex(const void* p, size_t n) {
  const unsigned char* b = static_cast<const unsigned char*>(p);
  std::ostringstream o; o << std::hex << std::setfill('0');
  for (size_t i=0;i<n;++i) o << std::setw(2) << (unsigned)b[i];
  return o.str();
}
template<typename POD> static std::string pod_to_hex(const POD& x){ return bytes_to_hex(&x,sizeof(POD)); }

int main(int argc, char** argv) {
  account_public_address addr{};
  crypto::secret_key spend_sec{}, view_sec{};
  crypto::generate_keys(addr.m_spend_public_key, spend_sec);
  crypto::generate_keys(addr.m_view_public_key,  view_sec);

  transaction tx{};
  const uint64_t height = 0;
  const size_t   median_weight = 0;
  const size_t   current_block_weight = 0;
  const uint64_t fee = 0;
  blobdata extra_nonce;                 // <-- use blobdata, not vector<uint8_t>
  const uint8_t hf_version = 1;

  // v0.18-style signature (height, no max_outs):
  bool ok = construct_miner_tx(height, median_weight, /*already_generated*/0,
                               current_block_weight, fee, addr, tx, extra_nonce,
                               hf_version);
  if (!ok) { std::cerr << "construct_miner_tx failed\n"; return 1; }

  std::string blob;
  if (!t_serializable_object_to_blob(tx, blob)) {
    std::cerr << "serialization failed\n"; return 1;
  }

  std::cout << "GENESIS_TX_HEX: " << bytes_to_hex(blob.data(), blob.size()) << "\n";
  std::cout << "GENESIS_ADDRESS: " << get_account_address_as_str(network_type::MAINNET,false,addr) << "\n";
  std::cout << "SPEND_SECRET_KEY: " << pod_to_hex(spend_sec) << "\n";
  std::cout << "VIEW_SECRET_KEY:  " << pod_to_hex(view_sec)  << "\n";
  return 0;
}
