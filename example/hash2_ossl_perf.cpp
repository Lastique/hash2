// Copyright 2024 Andrey Semashev.
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#define _CRT_SECURE_NO_WARNINGS

#include <boost/hash2/sha1.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/core/functor.hpp>
#include <boost/core/fclose_deleter.hpp>
#include <array>
#include <chrono>
#include <memory>
#include <utility>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <openssl/evp.h>

template< auto MD, std::size_t BlockSize, std::size_t DigestSize >
class openssl_block_hash
{
public:
    using result_type = std::array< std::uint8_t, DigestSize >;
    static constexpr std::size_t block_size = BlockSize;

private:
    std::unique_ptr< EVP_MD_CTX, boost::core::functor< EVP_MD_CTX_free > > m_ctx;

public:
    openssl_block_hash() : m_ctx(EVP_MD_CTX_new())
    {
        EVP_DigestInit(m_ctx.get(), MD());
    }

    openssl_block_hash(openssl_block_hash const& that) : m_ctx(EVP_MD_CTX_new())
    {
        EVP_MD_CTX_copy(m_ctx.get(), that.m_ctx.get());
    }

    openssl_block_hash& operator=(openssl_block_hash const& that)
    {
        openssl_block_hash tmp(that);
        m_ctx.swap(tmp.m_ctx);
        return *this;
    }

    openssl_block_hash(openssl_block_hash&&) = default;
    openssl_block_hash& operator= (openssl_block_hash&&) = default;

    void update(const void* data, std::size_t size)
    {
        EVP_DigestUpdate(m_ctx.get(), data, size);
    }

    result_type result()
    {
        result_type res;
        unsigned int s = 0u;
        EVP_DigestFinal_ex(m_ctx.get(), res.data(), &s);
        return res;
    }
};

using openssl_sha1_160 = openssl_block_hash< EVP_sha1, 64u, 20u >;
using openssl_sha2_256 = openssl_block_hash< EVP_sha256, 64u, 32u >;
using openssl_sha2_512 = openssl_block_hash< EVP_sha512, 128u, 64u >;


template< typename Hash >
void compute_hash(const std::uint8_t* data, std::size_t size)
{
    Hash hash;
    hash.update(data, size);
    auto result = hash.result();
    __asm__ __volatile__ ("" : : "m" (result));
}

using compute_hash_t = void (const std::uint8_t* data, std::size_t size);

constexpr std::pair< compute_hash_t*, const char* > compute_hash_funcs[] =
{
    { &compute_hash< boost::hash2::sha1_160 >, "sha1_160" },
    { &compute_hash< boost::hash2::sha2_256 >, "sha2_256" },
    { &compute_hash< boost::hash2::sha2_512 >, "sha2_512" },
    { &compute_hash< openssl_sha1_160 >, "openssl_sha1_160" },
    { &compute_hash< openssl_sha2_256 >, "openssl_sha2_256" },
    { &compute_hash< openssl_sha2_512 >, "openssl_sha2_512" }
};

void test_perf(compute_hash_t* func, const char* name, unsigned int iterations, const std::uint8_t* data, std::size_t size)
{
    const auto start = std::chrono::steady_clock::now();

    for (unsigned int i = 0u; i < iterations; ++i)
    {
        func(data, size);
    }

    const auto finish = std::chrono::steady_clock::now();

    double throughput = (static_cast< double >(size) * iterations) /
        (static_cast< double >(std::chrono::duration_cast< std::chrono::microseconds >(finish - start).count()) * 1.048576);
    std::printf("%s (%lu bytes): %0.6f MiB/s\n", name, static_cast< unsigned long >(size), throughput);
    std::fflush(stdout);
}

constexpr std::pair< std::size_t, unsigned int > test_params[] =
{
    { 1024u, 10'000u },
    { 1024u * 1024u, 1'000u },
    { 16u * 1024u * 1024u, 200u }
};

int main( int argc, char const* argv[] )
{
    const std::size_t max_buf_size = test_params[sizeof(test_params) / sizeof(*test_params) - 1u].first;
    std::unique_ptr< std::uint8_t[] > buffer(new std::uint8_t[max_buf_size]);

    {
        std::unique_ptr< std::FILE, boost::fclose_deleter > f(std::fopen("/dev/urandom", "rb"));
        std::fread(buffer.get(), 1, max_buf_size, f.get());
    }

    for (auto const& func_info : compute_hash_funcs)
    {
        for (auto const& params : test_params)
            test_perf(func_info.first, func_info.second, params.second, buffer.get(), params.first);
    }
}
