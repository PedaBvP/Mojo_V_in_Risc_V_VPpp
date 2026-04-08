#include "ml_kem.h"

#include <memory>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/provider.h>

namespace {

struct BioDeleter {
    void operator()(BIO* p) const noexcept {
        if (p) {
            BIO_free(p);
        }
    }
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept {
        if (p) {
            EVP_PKEY_free(p);
        }
    }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const noexcept {
        if (p) {
            EVP_PKEY_CTX_free(p);
        }
    }
};

struct EvpMdDeleter {
    void operator()(EVP_MD* p) const noexcept {
        if (p) {
            EVP_MD_free(p);
        }
    }
};

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* p) const noexcept {
        if (p) {
            EVP_MD_CTX_free(p);
        }
    }
};

struct EvpKdfDeleter {
    void operator()(EVP_KDF* p) const noexcept {
        if (p) {
            EVP_KDF_free(p);
        }
    }
};

struct EvpKdfCtxDeleter {
    void operator()(EVP_KDF_CTX* p) const noexcept {
        if (p) {
            EVP_KDF_CTX_free(p);
        }
    }
};

struct OssProviderDeleter {
    void operator()(OSSL_PROVIDER* p) const noexcept {
        if (p) {
            OSSL_PROVIDER_unload(p);
        }
    }
};

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpMdPtr = std::unique_ptr<EVP_MD, EvpMdDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using EvpKdfPtr = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;
using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;
using OssProviderPtr = std::unique_ptr<OSSL_PROVIDER, OssProviderDeleter>;

class SensitiveBuffer {
public:
    SensitiveBuffer() = default;

    explicit SensitiveBuffer(std::size_t size)
        : data_(size) {}

    SensitiveBuffer(const SensitiveBuffer&) = delete;
    SensitiveBuffer& operator=(const SensitiveBuffer&) = delete;

    SensitiveBuffer(SensitiveBuffer&& other) noexcept
        : data_(std::move(other.data_)) {}

    SensitiveBuffer& operator=(SensitiveBuffer&& other) noexcept {
        if (this != &other) {
            cleanse();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    ~SensitiveBuffer() {
        cleanse();
    }

    unsigned char* data() noexcept {
        return data_.empty() ? nullptr : data_.data();
    }

    const unsigned char* data() const noexcept {
        return data_.empty() ? nullptr : data_.data();
    }

    std::size_t size() const noexcept {
        return data_.size();
    }

    bool empty() const noexcept {
        return data_.empty();
    }

    void resize(std::size_t n) {
        cleanse();
        data_.resize(n);
    }

    std::vector<unsigned char> release_to_vector() && {
        return std::move(data_);
    }

private:
    void cleanse() noexcept {
        if (!data_.empty()) {
            OPENSSL_cleanse(data_.data(), data_.size());
        }
    }

    std::vector<unsigned char> data_;
};

}  // namespace

EVP_PKEY* ml_kem_read_privkey_pem(const char* path) {
    if (!path || !*path) {
        return nullptr;
    }

    BioPtr bio(BIO_new_file(path, "rb"));
    if (!bio) {
        return nullptr;
    }

    return PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
}

bool ml_kem_sha256_bytes(const unsigned char* in,
                         std::size_t inlen,
                         std::array<unsigned char, 32>& out32) {
    if (!in) {
        return false;
    }

    EvpMdPtr md(EVP_MD_fetch(nullptr, "SHA256", nullptr));
    if (!md) {
        return false;
    }

    EvpMdCtxPtr mctx(EVP_MD_CTX_new());
    if (!mctx) {
        return false;
    }

    unsigned int outlen = 0;

    if (EVP_DigestInit_ex(mctx.get(), md.get(), nullptr) != 1) {
        return false;
    }

    if (EVP_DigestUpdate(mctx.get(), in, inlen) != 1) {
        return false;
    }

    if (EVP_DigestFinal_ex(mctx.get(), out32.data(), &outlen) != 1) {
        return false;
    }

    return outlen == out32.size();
}

bool ml_kem_hkdf_sha256_key128(const unsigned char* ss,
                               std::size_t ss_len,
                               std::array<unsigned char, 16>& key_out) {
    if (!ss || ss_len == 0) {
        return false;
    }

    EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) {
        return false;
    }

    EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
    if (!kctx) {
        return false;
    }

    static const unsigned char salt[] = "dc-multitool-salt";
    static const unsigned char info[] = "mlkem512-simon128-data_contract";

    char digest_name[] = "SHA256";

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                          const_cast<unsigned char*>(ss),
                                          ss_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          const_cast<unsigned char*>(salt),
                                          sizeof(salt) - 1),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          const_cast<unsigned char*>(info),
                                          sizeof(info) - 1),
        OSSL_PARAM_construct_end()
    };

    return EVP_KDF_derive(kctx.get(), key_out.data(), key_out.size(), params) == 1;
}

bool ml_kem_decapsulate_shared_secret(const char* sk_pem_path,
                                      const unsigned char* kem_ct,
                                      std::size_t kem_ct_len,
                                      std::vector<unsigned char>& out_ss) {

    out_ss.clear();

    if (!sk_pem_path || !*sk_pem_path) {
        return false;
    }

    if (!kem_ct || kem_ct_len == 0) {
        return false;
    }

    OssProviderPtr provider(OSSL_PROVIDER_load(nullptr, "default"));
    if (!provider) {
        return false;
    }

    EvpPkeyPtr sk(ml_kem_read_privkey_pem(sk_pem_path));
    if (!sk) {
        return false;
    }

    EvpPkeyCtxPtr dctx(EVP_PKEY_CTX_new_from_pkey(nullptr, sk.get(), nullptr));
    if (!dctx) {
        return false;
    }

    if (EVP_PKEY_decapsulate_init(dctx.get(), nullptr) != 1) {
        return false;
    }

    std::size_t ss_len = 0;
    if (EVP_PKEY_decapsulate(dctx.get(), nullptr, &ss_len, kem_ct, kem_ct_len) != 1) {
        return false;
    }

    if (ss_len == 0) {
        return false;
    }

    SensitiveBuffer ss(ss_len);

    if (!ss.data()) {
        return false;
    }

    if (EVP_PKEY_decapsulate(dctx.get(), ss.data(), &ss_len, kem_ct, kem_ct_len) != 1) {
        return false;
    }

    if (ss_len != ss.size()) {
        SensitiveBuffer resized(ss_len);
        if (!resized.data()) {
            return false;
        }

        std::copy_n(ss.data(), ss_len, resized.data());
        out_ss = std::move(resized).release_to_vector();
    } else {
        out_ss = std::move(ss).release_to_vector();
    }

    return true;
}

bool ml_kem_decapsulate_to_key128(const char* sk_pem_path,
                                  const unsigned char* kem_ct,
                                  std::size_t kem_ct_len,
                                  std::array<unsigned char, 16>& out_key) {

    std::vector<unsigned char> ss;
    if (!ml_kem_decapsulate_shared_secret(sk_pem_path, kem_ct, kem_ct_len, ss, status)) {
        return false;
    }

    const bool ok = ml_kem_hkdf_sha256_key128(ss.data(), ss.size(), out_key);

    OPENSSL_cleanse(ss.data(), ss.size());
    ss.clear();

    return ok;
}