// UmbraHash GPU kernels — byte-for-byte identical to the CPU
// engine/mining/algorithms/umbrahash.rs. SHA3-256/512 (NIST) + FNV + Ethash-style
// dataset-item generation and hashimoto. Address-space note: NVIDIA's OpenCL
// treats unqualified pointer params as __generic; ctx/leaf pointers are qualified
// __private explicitly (same lesson as the ShadowHash kernel).

// ───────────────────────── Keccak-f1600 ─────────────────────────
__constant ulong KECCAK_RC[24] = {
0x0000000000000001UL,0x0000000000008082UL,0x800000000000808aUL,0x8000000080008000UL,
0x000000000000808bUL,0x0000000080000001UL,0x8000000080008081UL,0x8000000000008009UL,
0x000000000000008aUL,0x0000000000000088UL,0x0000000080008009UL,0x000000008000000aUL,
0x000000008000808bUL,0x800000000000008bUL,0x8000000000008089UL,0x8000000000008003UL,
0x8000000000008002UL,0x8000000000000080UL,0x000000000000800aUL,0x800000008000000aUL,
0x8000000080008081UL,0x8000000000008080UL,0x0000000080000001UL,0x8000000080008008UL };
__constant int KECCAK_ROTC[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
__constant int KECCAK_PILN[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

inline ulong rotl64(ulong x, int n){ return (x<<n)|(x>>(64-n)); }

void keccakf(__private ulong* st) {
    ulong t, bc[5];
    for (int r=0;r<24;r++){
        for (int i=0;i<5;i++) bc[i]=st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];
        for (int i=0;i<5;i++){ t=bc[(i+4)%5]^rotl64(bc[(i+1)%5],1); for(int j=0;j<25;j+=5) st[j+i]^=t; }
        t=st[1];
        for (int i=0;i<24;i++){ int j=KECCAK_PILN[i]; bc[0]=st[j]; st[j]=rotl64(t,KECCAK_ROTC[i]); t=bc[0]; }
        for (int j=0;j<25;j+=5){ for(int i=0;i<5;i++) bc[i]=st[j+i]; for(int i=0;i<5;i++) st[j+i]^=(~bc[(i+1)%5])&bc[(i+2)%5]; }
        st[0]^=KECCAK_RC[r];
    }
}

// SHA3 with configurable rate (72 => SHA3-512, 136 => SHA3-256). Output <= rate
// so a single squeeze suffices. All inputs are private/small here.
void sha3(__private const uchar* msg, uint len, uint rate, __private uchar* out, uint outlen) {
    ulong st[25]; for (int i=0;i<25;i++) st[i]=0;
    uint pos=0;
    for (uint i=0;i<len;i++){
        st[pos>>3] ^= ((ulong)msg[i]) << ((pos&7)*8);
        if (++pos==rate){ keccakf(st); pos=0; }
    }
    st[pos>>3] ^= ((ulong)0x06) << ((pos&7)*8);
    st[(rate-1)>>3] ^= ((ulong)0x80) << (((rate-1)&7)*8);
    keccakf(st);
    for (uint i=0;i<outlen;i++) out[i] = (uchar)(st[i>>3] >> ((i&7)*8));
}

// ───────────────────────── FNV + little-endian word helpers ─────────────────
inline uint fnv(uint a, uint b){ return a*0x01000193u ^ b; }
inline uint u32le_p(__private const uchar* b, uint word){ uint o=word*4u; return (uint)b[o]|((uint)b[o+1]<<8)|((uint)b[o+2]<<16)|((uint)b[o+3]<<24); }
inline uint u32le_gb(__global const uchar* b, uint off){ return (uint)b[off]|((uint)b[off+1]<<8)|((uint)b[off+2]<<16)|((uint)b[off+3]<<24); }
inline void put_u32le_p(__private uchar* b, uint word, uint v){ uint o=word*4u; b[o]=(uchar)v; b[o+1]=(uchar)(v>>8); b[o+2]=(uchar)(v>>16); b[o+3]=(uchar)(v>>24); }

// One 64-byte dataset item from the cache (n = cache items). Matches CPU exactly.
void calc_item(__global const uchar* cache, uint n, uint i, __private uchar* out) {
    uchar mix[64];
    uint start = (i % n) * 64u;
    for (uint k=0;k<64;k++) mix[k]=cache[start+k];
    put_u32le_p(mix, 0, u32le_p(mix,0) ^ i);
    uchar tmp[64];
    sha3(mix, 64, 72, tmp, 64);          // SHA3-512
    for (uint k=0;k<64;k++) mix[k]=tmp[k];
    for (uint j=0;j<256u;j++){
        uint ci = fnv(i ^ j, u32le_p(mix, j % 16u)) % n;
        uint coff = ci*64u;
        for (uint word=0; word<16u; word++){
            uint f = fnv(u32le_p(mix, word), u32le_gb(cache, coff + word*4u));
            put_u32le_p(mix, word, f);
        }
    }
    sha3(mix, 64, 72, out, 64);          // SHA3-512
}

__kernel void umbra_calc_items(__global const uchar* cache, uint n, uint base, __global uchar* out) {
    uint gid = get_global_id(0);
    uchar item[64];
    calc_item(cache, n, base + gid, item);
    // Write at the ABSOLUTE item index so this kernel can fill the full dataset
    // buffer in batches (out[(base+gid)*64 ..]). With base=0 this is out[gid*64].
    ulong off = ((ulong)base + gid) * 64u;
    for (uint k=0;k<64;k++) out[off+k]=item[k];
}

// hashimoto over a resident dataset (n items). Returns mix_hash(32) + result(32).
void hashimoto_full_dev(__global const uchar* dataset, uint n,
                        __private const uchar* header_hash, ulong nonce,
                        __private uchar* mix_out, __private uchar* result_out) {
    uchar seed_in[40];
    for (uint k=0;k<32;k++) seed_in[k]=header_hash[k];
    for (uint k=0;k<8;k++)  seed_in[32+k]=(uchar)(nonce >> (8u*k));
    uchar s[64];
    sha3(seed_in, 40, 72, s, 64);        // SHA3-512

    uchar mix[128];
    for (uint k=0;k<64;k++){ mix[k]=s[k]; mix[64+k]=s[k]; }
    uint s0 = u32le_p(s, 0);
    uint w = 32u, mixhashes = 2u;

    for (uint i=0;i<64u;i++){
        uint p = (fnv(i ^ s0, u32le_p(mix, i % w)) % (n / mixhashes)) * mixhashes;
        uchar newdata[128];
        for (uint k=0;k<128u;k++) newdata[k]=dataset[p*64u + k];
        for (uint word=0; word<w; word++){
            uint f = fnv(u32le_p(mix, word), u32le_p(newdata, word));
            put_u32le_p(mix, word, f);
        }
    }
    for (uint i=0;i<8u;i++){
        uint f = fnv(fnv(fnv(u32le_p(mix,4*i), u32le_p(mix,4*i+1)), u32le_p(mix,4*i+2)), u32le_p(mix,4*i+3));
        put_u32le_p(mix_out, i, f);
    }
    uchar res_in[96];
    for (uint k=0;k<64;k++) res_in[k]=s[k];
    for (uint k=0;k<32;k++) res_in[64+k]=mix_out[k];
    sha3(res_in, 96, 136, result_out, 32); // SHA3-256
}

// Validation kernel: one (mix_hash,result) per input nonce.
__kernel void umbra_hashimoto(__global const uchar* dataset, uint n,
                              __global const uchar* header_hash,
                              __global const ulong* nonces, __global uchar* out) {
    uint gid = get_global_id(0);
    uchar hh[32]; for (uint k=0;k<32;k++) hh[k]=header_hash[k];
    uchar mix[32], res[32];
    hashimoto_full_dev(dataset, n, hh, nonces[gid], mix, res);
    for (uint k=0;k<32;k++){ out[gid*64u+k]=mix[k]; out[gid*64u+32+k]=res[k]; }
}

// Mining kernel: search nonces = base+gid; record the first whose result <=
// target (big-endian). result[0]=count, [1]=nonce_lo, [2]=nonce_hi; winner's
// 32-byte mix_hash written to win_mix.
__kernel void umbra_mine(__global const uchar* dataset, uint n,
                         __global const uchar* header_hash, ulong base_nonce,
                         __global const uchar* target,
                         __global uint* result, __global uchar* win_mix) {
    uint gid = get_global_id(0);
    ulong nonce = base_nonce + (ulong)gid;
    uchar hh[32]; for (uint k=0;k<32;k++) hh[k]=header_hash[k];
    uchar mix[32], res[32];
    hashimoto_full_dev(dataset, n, hh, nonce, mix, res);
    bool meets = true;
    for (uint i=0;i<32u;i++){ if(res[i]<target[i]){meets=true;break;} if(res[i]>target[i]){meets=false;break;} }
    if (meets){
        uint slot = atomic_inc(&result[0]);
        if (slot==0){
            result[1]=(uint)(nonce & 0xffffffffu); result[2]=(uint)(nonce>>32);
            for (uint k=0;k<32;k++) win_mix[k]=mix[k];
        }
    }
}
