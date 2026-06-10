#include "rmtls_threshold_mlkem/mlkem_adapter.hpp"

#include <iostream>

#if defined(RMTLS_ENABLE_TEST_OBSERVERS)
#error "Production API test inherited test-only observer support"
#endif

using namespace rmtls;

template <class T>
concept HasPeerSessionPreparation = requires(
    const T& adapter,
    const Secret<Bytes>& secret,
    const std::string& context) {
    adapter.prepare_peer_session_for_test(secret, context);
};

int main() {
    static_assert(!HasPeerSessionPreparation<MLKEMAdapter>);
    std::cout << "test_production_api passed\n";
    return 0;
}
