#ifndef BOOST_HASH2_GET_INTEGRAL_RESULT_HPP_INCLUDED
#define BOOST_HASH2_GET_INTEGRAL_RESULT_HPP_INCLUDED

// Copyright 2017, 2018 Peter Dimov.
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/hash2/digest.hpp>
#include <boost/hash2/detail/read.hpp>
#include <array>
#include <type_traits>
#include <cstddef>

namespace boost
{
namespace hash2
{

template<class T, class R>
    typename std::enable_if<std::is_integral<R>::value && (sizeof(R) >= sizeof(T)), T>::type
    get_integral_result( R const & r )
{
    typedef typename std::make_unsigned<T>::type U;
    return static_cast<T>( static_cast<U>( r ) );
}

template<class T, class R>
    typename std::enable_if<std::is_integral<R>::value && sizeof(R) == 4 && sizeof(T) == 8, T>::type
    get_integral_result( R const & r )
{
    typedef typename std::make_unsigned<T>::type U;
    return static_cast<T>( ( static_cast<U>( r ) << 32 ) + r );
}

template<class T, std::size_t N>
    T get_integral_result( std::array<unsigned char, N> const & r )
{
    static_assert( N >= 8, "Array result type is too short" );
    return static_cast<T>( detail::read64le( r.data() ) );
}

template<class T, std::size_t N>
    T get_integral_result( digest<N> const & r )
{
    static_assert( N >= 8, "Digest result type is too short" );
    return static_cast<T>( detail::read64le( r.data() ) );
}

} // namespace hash2
} // namespace boost

#endif // #ifndef BOOST_HASH2_GET_INTEGRAL_RESULT_HPP_INCLUDED
