#ifndef BOOST_HASH2_HMAC_HPP_INCLUDED
#define BOOST_HASH2_HMAC_HPP_INCLUDED

// Copyright 2017, 2018 Peter Dimov.
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// HMAC message authentication algorithm, https://tools.ietf.org/html/rfc2104

#include <boost/hash2/detail/write.hpp>
#include <boost/assert.hpp>
#include <cstdint>
#include <cstring>
#include <cstddef>

namespace boost
{
namespace hash2
{

template<class H> class hmac
{
public:

    typedef typename H::result_type result_type;

    static const int block_size = H::block_size;

private:

    H outer_;
    H inner_;

private:

    void init( unsigned char const * p, std::size_t n )
    {
        int const m = block_size;

        unsigned char key[ m ] = {};

        if( n == 0 )
        {
            // memcpy from (NULL, 0) is undefined
        }
        else if( n <= m )
        {
            std::memcpy( key, p, n );
        }
        else
        {
            H h;

            h.update( p, n );

            result_type r = h.result();

            std::memcpy( key, &r[0], r.size() );
        }

        for( int i = 0; i < m; ++i )
        {
            key[ i ] = static_cast<unsigned char>( key[ i ] ^ 0x36 );
        }

        inner_.update( key, m );

        for( int i = 0; i < m; ++i )
        {
            key[ i ] = static_cast<unsigned char>( key[ i ] ^ 0x36 ^ 0x5C );
        }

        outer_.update( key, m );
    }

public:

    hmac()
    {
        init( 0, 0 );
    }

    explicit hmac( std::uint64_t seed )
    {
        if( seed == 0 )
        {
            init( 0, 0 );
        }
        else
        {
            unsigned char tmp[ 8 ];
            detail::write64le( tmp, seed );

            init( tmp, 8 );
        }
    }

    hmac( unsigned char const * p, std::size_t n )
    {
        init( p, n );
    }

    void update( void const * pv, std::size_t n )
    {
        inner_.update( pv, n );
    }

    result_type result()
    {
        result_type r = inner_.result();

        outer_.update( &r[0], r.size() );

        return outer_.result();
    }
};

} // namespace hash2
} // namespace boost

#endif // #ifndef BOOST_HASH2_HMAC_HPP_INCLUDED
