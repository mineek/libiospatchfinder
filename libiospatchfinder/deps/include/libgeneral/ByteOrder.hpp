//
//  ByteOrder.hpp
//  libgeneral
//
//  Created by erd on 04.08.23.
//  Copyright © 2023 tihmstar. All rights reserved.
//

#ifndef ByteOrder_h
#define ByteOrder_h

#include <stdint.h>
#include <codecvt>
#include <locale>
#include <iostream>

#ifdef __APPLE__
#   include <libkern/OSByteOrder.h>
#   define bswap_16(x) _OSSwapInt16(x)
#   define bswap_32(x) _OSSwapInt32(x)
#   define bswap_64(x) _OSSwapInt64(x)
#elif 0 //HEADER_HAVE_BYTESWAP_H
#   include <byteswap.h>
#endif

#if 0 //HEADER_HAVE_ENDIAN_H
#   include <endian.h>
#endif

#if 1 //HEADER_HAVE_ARPA_INET_H
#define MAYBE_CONSTEXPR constexpr inline
#   include <arpa/inet.h>
#elif 0 //HEADER_HAVE_WINSOCK_H
#define MAYBE_CONSTEXPR inline
#   include <winsock.h>
#   include <sys/param.h>
#   define bswap_16(x) __builtin_bswap16(x)
#   define bswap_32(x) __builtin_bswap32(x)
#   define bswap_64(x) __builtin_bswap64(x)
#else
#error needs htons and friends
#endif

#ifdef __APPLE__
MAYBE_CONSTEXPR bool isBigEndianSystem(){
#   if __DARWIN_BYTE_ORDER == __DARWIN_BIG_ENDIAN
    return true;
#   else
    return false;
#   endif
}
#elif defined(BYTE_ORDER)
MAYBE_CONSTEXPR bool isBigEndianSystem(){
#   if BYTE_ORDER == BIG_ENDIAN
    return true;
#   else
    return false;
#   endif
}
#else
inline bool isBigEndianSystem(){
    return htonl(1) == 1;
}
#endif

#if !1 //FUNC_HAVE_DECL_HTONLL
#   if 0 //HEADER_HAVE_ENDIAN_H
#       define htonll(x) htobe64(x)
#       define ntohll(x) be64toh(x)
#   else //HEADER_HAVE_ENDIAN_H
inline uint64_t htonll(uint64_t x){
    if (isBigEndianSystem()) {
        //big endian system
        return x;
    }else{
        uint32_t l = x & 0xffffffff;
        uint32_t u = (x>>32) & 0xffffffff;
        return (((uint64_t)htonl(l)) << 32) | htonl(u);
    }
}
#       define ntohll htonll
#   endif //HEADER_HAVE_ENDIAN_H
#endif //!FUNC_HAVE_DECL_HTONLL

template <typename T>
inline T byteOrder_BE(T num);

template <typename T>
inline T byteOrder_HO(T num);

template <typename T>
inline T byteOrder_LE(T num);

#pragma mark implementation BE
template<>
MAYBE_CONSTEXPR uint8_t byteOrder_BE<uint8_t>(uint8_t num){
    return num;
}

template<>
MAYBE_CONSTEXPR int8_t byteOrder_BE<int8_t>(int8_t num){
    return num;
}

template<>
inline uint16_t byteOrder_BE<uint16_t>(uint16_t num){
    return htons(num);
}

template<>
inline int16_t byteOrder_BE<int16_t>(int16_t num){
    return htons(num);
}

template<>
inline uint32_t byteOrder_BE<uint32_t>(uint32_t num){
    return htonl(num);
}

template<>
inline int32_t byteOrder_BE<int32_t>(int32_t num){
    return htonl(num);
}

template<>
inline uint64_t byteOrder_BE<uint64_t>(uint64_t num){
    return htonll(num);
}

template<>
inline int64_t byteOrder_BE<int64_t>(int64_t num){
    return htonll(num);
}

#pragma mark implementation HO
template<>
MAYBE_CONSTEXPR uint8_t byteOrder_HO<uint8_t>(uint8_t num){
    return num;
}

template<>
MAYBE_CONSTEXPR int8_t byteOrder_HO<int8_t>(int8_t num){
    return num;
}

template<>
inline uint16_t byteOrder_HO<uint16_t>(uint16_t num){
    return ntohs(num);
}

template<>
inline int16_t byteOrder_HO<int16_t>(int16_t num){
    return ntohs(num);
}

template<>
inline uint32_t byteOrder_HO<uint32_t>(uint32_t num){
    return ntohl(num);
}

template<>
inline int32_t byteOrder_HO<int32_t>(int32_t num){
    return ntohl(num);
}

template<>
inline uint64_t byteOrder_HO<uint64_t>(uint64_t num){
    return ntohll(num);
}

template<>
inline int64_t byteOrder_HO<int64_t>(int64_t num){
    return ntohll(num);
}

#pragma mark implementation LE
template<>
MAYBE_CONSTEXPR uint8_t byteOrder_LE<uint8_t>(uint8_t num){
    return num;
}

template<>
MAYBE_CONSTEXPR int8_t byteOrder_LE<int8_t>(int8_t num){
    return num;
}

template<>
inline uint16_t byteOrder_LE<uint16_t>(uint16_t num){
#if 0 //HEADER_HAVE_ENDIAN_H
    return htole16(num);
#else
    return isBigEndianSystem() ? num : bswap_16(num);
#endif
}

template<>
inline int16_t byteOrder_LE<int16_t>(int16_t num){
#if 0 //HEADER_HAVE_ENDIAN_H
    return htole16((uint16_t)num);
#else
    return isBigEndianSystem() ? num : bswap_16(num);
#endif
}

template<>
inline uint32_t byteOrder_LE<uint32_t>(uint32_t num){
#if 0 //HEADER_HAVE_ENDIAN_H
    return htole32(num);
#else
    return isBigEndianSystem() ? num : bswap_32(num);
#endif
}

template<>
inline int32_t byteOrder_LE<int32_t>(int32_t num){
#if 0 //HEADER_HAVE_ENDIAN_H
    return htole32((uint32_t)num);
#else
    return isBigEndianSystem() ? num : bswap_32(num);
#endif
}

template<>
inline uint64_t byteOrder_LE<uint64_t>(uint64_t num){
#if 0 //HEADER_HAVE_ENDIAN_H
    return htole64(num);
#else
    return isBigEndianSystem() ? num : bswap_64(num);
#endif
}

template<>
inline int64_t byteOrder_LE<int64_t>(int64_t num){
#if 0 //HEADER_HAVE_ENDIAN_H
    return htole64((uint64_t)num);
#else
    return isBigEndianSystem() ? num : bswap_64(num);
#endif
}

#define cnvBE(x) byteOrder_BE(x)
#define cnvHO(x) byteOrder_HO(x)
#define cnvLE(x) byteOrder_LE(x)


#pragma mark UTF-16
inline std::wstring strToWstr(const char *s){
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(s);
}

inline std::wstring strToWstr(std::string s){
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(s);
}

inline std::string wstrToStr(const std::wstring& str){
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}

#pragma mark UTF-32
inline std::u32string strToW32str(const char *s){
    std::wstring_convert<std::codecvt_utf8<char32_t>,char32_t> converter;
    return converter.from_bytes(s);
}

inline std::u32string strToW32str(std::string s){
    std::wstring_convert<std::codecvt_utf8<char32_t>,char32_t> converter;
    return converter.from_bytes(s);
}

inline std::string w32strToStr(const std::u32string& str){
    std::wstring_convert<std::codecvt_utf8<char32_t>,char32_t> myconv;
    return myconv.to_bytes(str);
}

#endif /* ByteOrder_h */
