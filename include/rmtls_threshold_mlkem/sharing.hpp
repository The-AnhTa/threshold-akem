#pragma once

#include "rmtls_threshold_mlkem/types.hpp"
#include <array>
#include <functional>
#include <map>

namespace rmtls {

class Assistant;
class Combiner;

struct PartyId {
    int value;
    friend bool operator<(PartyId a, PartyId b) { return a.value < b.value; }
    friend bool operator==(PartyId a, PartyId b) { return a.value == b.value; }
};

struct ShareContext {
    std::string service_kem_fingerprint;
    std::string threshold_key_id;
    std::string assistant_epoch;
    std::string adapter_profile_id;

    friend bool operator==(const ShareContext&, const ShareContext&) = default;
};

using ShareSetId = std::array<std::uint8_t, 32>;

class ShareVector {
public:
    ShareVector(const ShareVector&) = delete;
    ShareVector& operator=(const ShareVector&) = delete;
    ShareVector(ShareVector&&) noexcept = default;
    ShareVector& operator=(ShareVector&&) noexcept = default;

    PartyId party() const { return party_; }
    bool is_erased_internal() const { return coeffs_.is_erased_internal(); }

private:
    friend class Assistant;
    friend class Combiner;
    friend class Shamir23;

    ShareVector(PartyId party,
                ShareContext context,
                ShareSetId share_set_id,
                CoeffVector coeffs)
        : party_(party),
          context_(std::move(context)),
          share_set_id_(share_set_id),
          coeffs_(Secret<CoeffVector>(std::move(coeffs))) {}

    PartyId party_;
    ShareContext context_;
    ShareSetId share_set_id_;
    Secret<CoeffVector> coeffs_;
};

class ShareMap {
public:
    ShareMap() = default;
    ShareMap(const ShareMap&) = delete;
    ShareMap& operator=(const ShareMap&) = delete;
    ShareMap(ShareMap&&) noexcept = default;
    ShareMap& operator=(ShareMap&&) noexcept = default;

    bool empty() const { return shares_.empty(); }
    std::size_t size() const { return shares_.size(); }

private:
    friend class Assistant;
    friend class Shamir23;

    std::map<PartyId, ShareVector> shares_;
};

Coeff add_q(Coeff a, Coeff b);
Coeff sub_q(Coeff a, Coeff b);
Coeff mul_q(Coeff a, Coeff b);
Coeff inv_q(Coeff a);
Coeff lagrange_at_zero(PartyId i, const std::vector<PartyId>& active);

class Shamir23 {
public:
    // Dealer path: share the wrapped key material and erase it on both success
    // and failure before returning control to the caller.
    static ShareMap share_and_erase(Secret<CoeffVector>& secret,
                                    const ShareContext& context);

private:
    friend class Combiner;

    static Secret<CoeffVector> reconstruct_values(
        const std::array<PartyId, 2>& parties,
        const std::array<ShareSetId, 2>& share_set_ids,
        const std::array<
            std::reference_wrapper<const Secret<CoeffVector>>,
            2>& values);

    // Share with uniformly sampled slopes from the operating system CSPRNG.
    static ShareMap share(const CoeffVector& secret,
                          const ShareContext& context);

};

} // namespace rmtls
