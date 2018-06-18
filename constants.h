#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#define VERSION "1.5.3"

#define SHA1BA(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t) (const uint8_t[]){0x##a,0x##b,0x##c,0x##d,0x##e,0x##f,0x##g,0x##h,0x##i,0x##j,0x##k,0x##l,0x##m,0x##n,0x##o,0x##p,0x##q,0x##r,0x##s,0x##t}

#define injector_swarm SHA1BA(DF,54,48,F4,78,17,1B,51,63,4C,E1,EB,58,18,20,05,18,5D,8C,05)
#define injector_proxy_swarm SHA1BA(34,AA,F4,94,0A,2C,2C,31,4D,C4,AF,03,D4,B5,F5,44,EE,82,2D,11)
#define encrypted_injector_swarm SHA1BA(DC,1B,08,0B,E3,A1,F3,34,16,32,19,F0,F8,B4,17,16,23,92,D4,BB)
#define encrypted_injector_proxy_swarm SHA1BA(58,27,A0,AD,A6,CA,B6,B8,71,76,DD,1D,5A,00,0B,B0,18,0A,1D,4B)

#ifdef DEBUG
#define injector_sk "\x9e\x20\xb0\x57\x6d\x12\x70\x33\x05\x42\x66\x4d\x07\x00\xfe\x0a\x60\x94\xe0\x9a\xc5\xb9\xad\x78\xb8\xa6\x56\x3e\x09\xf7\x2a\xd2\x1d\x80\x27\x79\xa0\xb9\x27\xd6\x87\x11\xec\xdc\x33\x7a\xe3\x91\x28\xb8\x07\xf1\xb5\x8c\x42\x74\xf3\xae\x09\xcd\x48\x10\x87\x96"
#define injector_pk "\x1d\x80\x27\x79\xa0\xb9\x27\xd6\x87\x11\xec\xdc\x33\x7a\xe3\x91\x28\xb8\x07\xf1\xb5\x8c\x42\x74\xf3\xae\x09\xcd\x48\x10\x87\x96"
#else
#define injector_pk "\xe5\x7d\x10\x3b\xf1\x49\x6d\x24\x9c\x1a\x9e\x83\x13\x1a\x75\xb5\xf6\x2e\x3a\x67\x7e\xb6\xab\x9d\x66\x77\x5f\xb4\x8a\xbe\x68\xfa"
#endif

#define hashed_headers {"Content-Location", "Content-Type", "Location", "Access-Control-Allow-Origin"}

#endif // __CONSTANTS_H__
