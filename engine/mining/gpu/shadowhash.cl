// Full ShadowHash pipeline in OpenCL. Mirrors engine/mining/algorithms/
// {shadowhash.rs, anti_asic.rs} byte-for-byte. Each work-item hashes one header
// using its own 256KB + 16KB global scratchpad region (memory-hard by design).

// ───────────────────────── SHA-256 (streaming ctx) ─────────────────────────
__constant uint SHA256_K[64] = {
0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

inline uint rotr32(uint x, uint n) { return (x >> n) | (x << (32u - n)); }

typedef struct { uint st[8]; uchar buf[64]; uint buflen; ulong total; } sha256_ctx;

void sha256_init(__private sha256_ctx* c) {
    c->st[0]=0x6a09e667u; c->st[1]=0xbb67ae85u; c->st[2]=0x3c6ef372u; c->st[3]=0xa54ff53au;
    c->st[4]=0x510e527fu; c->st[5]=0x9b05688cu; c->st[6]=0x1f83d9abu; c->st[7]=0x5be0cd19u;
    c->buflen=0; c->total=0;
}

void sha256_compress(__private uint* st, __private const uchar* blk) {
    uint w[64];
    for (uint t=0;t<16;t++)
        w[t]=((uint)blk[t*4]<<24)|((uint)blk[t*4+1]<<16)|((uint)blk[t*4+2]<<8)|((uint)blk[t*4+3]);
    for (uint t=16;t<64;t++){
        uint s0=rotr32(w[t-15],7)^rotr32(w[t-15],18)^(w[t-15]>>3);
        uint s1=rotr32(w[t-2],17)^rotr32(w[t-2],19)^(w[t-2]>>10);
        w[t]=w[t-16]+s0+w[t-7]+s1;
    }
    uint a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
    for (uint t=0;t<64;t++){
        uint S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
        uint ch=(e&f)^((~e)&g);
        uint t1=h+S1+ch+SHA256_K[t]+w[t];
        uint S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
        uint maj=(a&b)^(a&c)^(b&c);
        uint t2=S0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

void sha256_push(__private sha256_ctx* c, uchar byte) {
    c->buf[c->buflen++]=byte; c->total++;
    if (c->buflen==64){ sha256_compress(c->st, c->buf); c->buflen=0; }
}
void sha256_update_priv(__private sha256_ctx* c, __private const uchar* d, uint len){ for(uint i=0;i<len;i++) sha256_push(c,d[i]); }
void sha256_update_glob(__private sha256_ctx* c, __global const uchar* d, uint len){ for(uint i=0;i<len;i++) sha256_push(c,d[i]); }

void sha256_final(__private sha256_ctx* c, __private uchar* out) {
    ulong bitlen = c->total*8u;
    sha256_push(c, 0x80);
    while (c->buflen != 56) sha256_push(c, 0x00);
    for (int k=7;k>=0;k--) sha256_push(c, (uchar)(bitlen >> (8*k)));
    for (uint i=0;i<8;i++){
        out[i*4+0]=(uchar)(c->st[i]>>24); out[i*4+1]=(uchar)(c->st[i]>>16);
        out[i*4+2]=(uchar)(c->st[i]>>8);  out[i*4+3]=(uchar)(c->st[i]);
    }
}

// ───────────────────────── Keccak / SHA3-256 (streaming ctx) ─────────────────
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

// SHA3-256: rate = 136 bytes, pad 0x06.../0x80.
typedef struct { ulong st[25]; uint pos; } sha3_ctx;

void sha3_init(__private sha3_ctx* c){ for(int i=0;i<25;i++) c->st[i]=0; c->pos=0; }
void sha3_absorb_byte(__private sha3_ctx* c, uchar b){
    int lane=c->pos>>3; int sh=(c->pos&7)*8;
    c->st[lane]^=((ulong)b)<<sh;
    c->pos++;
    if (c->pos==136){ keccakf(c->st); c->pos=0; }
}
void sha3_update_priv(__private sha3_ctx* c, __private const uchar* d, uint len){ for(uint i=0;i<len;i++) sha3_absorb_byte(c,d[i]); }
void sha3_update_glob(__private sha3_ctx* c, __global const uchar* d, uint len){ for(uint i=0;i<len;i++) sha3_absorb_byte(c,d[i]); }
void sha3_final(__private sha3_ctx* c, __private uchar* out){
    // pad: 0x06 at pos, 0x80 at 135
    int lane=c->pos>>3; int sh=(c->pos&7)*8;
    c->st[lane]^=((ulong)0x06)<<sh;
    c->st[135>>3]^=((ulong)0x80)<<((135&7)*8);
    keccakf(c->st);
    for (uint i=0;i<32;i++){ int l=i>>3; int s=(i&7)*8; out[i]=(uchar)(c->st[l]>>s); }
}

// ───────────────────────── byte helpers ─────────────────
inline uchar rol8(uchar x, uint n){ n&=7u; if(n==0) return x; return (uchar)((x<<n)|(x>>(8u-n))); }
inline uchar revbits8(uchar x){
    x=(uchar)(((x&0xF0)>>4)|((x&0x0F)<<4));
    x=(uchar)(((x&0xCC)>>2)|((x&0x33)<<2));
    x=(uchar)(((x&0xAA)>>1)|((x&0x55)<<1));
    return x;
}

#define SP256 262144u
#define SP16  16384u

// anti_asic hardening of a 32-byte input -> 32-byte out. Uses this work-item's
// 16KB global scratchpad region `sp16`.
void anti_asic(__private const uchar* in32, __global uchar* sp16, __private uchar* out) {
    // stage1 = SHA3-256("ShadowDAG_AntiASIC_v1" || in32)
    sha3_ctx s3; sha3_init(&s3);
    const uchar tag[21]={'S','h','a','d','o','w','D','A','G','_','A','n','t','i','A','S','I','C','_','v','1'};
    sha3_update_priv(&s3, tag, 21);
    sha3_update_priv(&s3, in32, 32);
    uchar stage1[32]; sha3_final(&s3, stage1);

    // 16KB scratchpad: chunk_i = SHA-256(stage1 || (i as u64 LE))
    for (uint i=0;i<SP16/32u;i++){
        sha256_ctx h; sha256_init(&h);
        sha256_update_priv(&h, stage1, 32);
        uchar il[8]; for(int k=0;k<8;k++) il[k]=(uchar)(((ulong)i)>>(8*k));
        sha256_update_priv(&h, il, 8);
        uchar blk[32]; sha256_final(&h, blk);
        for (uint j=0;j<32;j++) sp16[i*32u+j]=blk[j];
    }

    // 256 data-dependent branch rounds
    for (uint i=0;i<256u;i++){
        uint idx = ((uint)stage1[i%32u]*64u) % (SP16-32u);
        uchar dir = sp16[idx] & 0x03u;
        if (dir==0){
            uint next=(idx+32u)%(SP16-32u);
            for (uint j=0;j<32u;j++) sp16[idx+j]^=sp16[next+j];
        } else if (dir==1){
            uchar temp=sp16[idx];
            for (uint j=0;j<31u;j++) sp16[idx+j]=sp16[idx+j+1u];
            sp16[idx+31u]=temp;
        } else if (dir==2){
            uint next=(idx+64u)%(SP16-32u);
            for (uint j=0;j<32u;j++) sp16[idx+j]=(uchar)(sp16[idx+j]+sp16[next+j]);
        } else {
            for (uint j=0;j<32u;j++) sp16[idx+j]=revbits8(sp16[idx+j]);
        }
    }

    // out = SHA3-256(scratchpad || stage1)
    sha3_ctx f; sha3_init(&f);
    sha3_update_glob(&f, sp16, SP16);
    sha3_update_priv(&f, stage1, 32);
    sha3_final(&f, out);
}

// Full ShadowHash of one header. sp256/sp16 are this item's private regions.
__kernel void shadowhash(__global const uchar* headers, uint hdr_len,
                         __global uchar* sp256_all, __global uchar* sp16_all,
                         __global uchar* out /* 128 bytes/item: round1,round2,anti,final */) {
    uint gid = get_global_id(0);
    __global const uchar* hdr = headers + gid*hdr_len;
    __global uchar* sp256 = sp256_all + (ulong)gid*SP256;
    __global uchar* sp16  = sp16_all  + (ulong)gid*SP16;

    // round1 = SHA-256(header)
    uchar round1[32];
    { sha256_ctx h; sha256_init(&h); sha256_update_glob(&h, hdr, hdr_len); sha256_final(&h, round1); }

    // 256KB scratchpad init: chunk_i = SHA-256(round1 || (i as u32 LE))
    for (uint i=0;i<SP256/32u;i++){
        sha256_ctx h; sha256_init(&h);
        sha256_update_priv(&h, round1, 32);
        uchar il[4]; il[0]=(uchar)i; il[1]=(uchar)(i>>8); il[2]=(uchar)(i>>16); il[3]=(uchar)(i>>24);
        sha256_update_priv(&h, il, 4);
        uchar blk[32]; sha256_final(&h, blk);
        for (uint j=0;j<32u;j++) sp256[i*32u+j]=blk[j];
    }

    // 16 mixing rounds (data-dependent, ulong rot_idx to match usize wrapping_mul)
    for (uint round=0; round<16u; round++){
        uint idx = ((uint)round1[round%32u]*256u + (uint)round1[(round+1u)%32u]) % (SP256-32u);
        uchar mix[32];
        for (uint j=0;j<32u;j++) mix[j]=sp256[idx+j];
        ulong rot_idx = ((ulong)idx * 0x9E3779B9UL) % (ulong)(SP256-32u);
        for (uint j=0;j<32u;j++){
            mix[j]^=sp256[(uint)rot_idx+j];
            mix[j]=rol8(mix[j], round%8u);
        }
        for (uint j=0;j<32u;j++) sp256[idx+j]=mix[j];
    }

    // round2 = SHA-256(scratchpad)
    uchar round2[32];
    { sha256_ctx h; sha256_init(&h); sha256_update_glob(&h, sp256, SP256); sha256_final(&h, round2); }

    // anti_asic
    uchar anti[32];
    anti_asic(round2, sp16, anti);

    // round3 = SHA3-256(round1 || round2 || anti || header)
    uchar finalh[32];
    { sha3_ctx s3; sha3_init(&s3);
      sha3_update_priv(&s3, round1, 32);
      sha3_update_priv(&s3, round2, 32);
      sha3_update_priv(&s3, anti, 32);
      sha3_update_glob(&s3, hdr, hdr_len);
      sha3_final(&s3, finalh); }

    __global uchar* o = out + (ulong)gid*128u;
    for (uint j=0;j<32u;j++){ o[j]=round1[j]; o[32+j]=round2[j]; o[64+j]=anti[j]; o[96+j]=finalh[j]; }
}

// Full ShadowHash of a PRIVATE header buffer -> finalh (used by the miner, which
// patches the nonce per work-item so each header differs).
void shadowhash_priv(__private const uchar* hdr, uint hdr_len,
                     __global uchar* sp256, __global uchar* sp16,
                     __private uchar* finalh) {
    uchar round1[32];
    { sha256_ctx h; sha256_init(&h); sha256_update_priv(&h, hdr, hdr_len); sha256_final(&h, round1); }
    for (uint i=0;i<SP256/32u;i++){
        sha256_ctx h; sha256_init(&h);
        sha256_update_priv(&h, round1, 32);
        uchar il[4]; il[0]=(uchar)i; il[1]=(uchar)(i>>8); il[2]=(uchar)(i>>16); il[3]=(uchar)(i>>24);
        sha256_update_priv(&h, il, 4);
        uchar blk[32]; sha256_final(&h, blk);
        for (uint j=0;j<32u;j++) sp256[i*32u+j]=blk[j];
    }
    for (uint round=0; round<16u; round++){
        uint idx = ((uint)round1[round%32u]*256u + (uint)round1[(round+1u)%32u]) % (SP256-32u);
        uchar mix[32];
        for (uint j=0;j<32u;j++) mix[j]=sp256[idx+j];
        ulong rot_idx = ((ulong)idx * 0x9E3779B9UL) % (ulong)(SP256-32u);
        for (uint j=0;j<32u;j++){ mix[j]^=sp256[(uint)rot_idx+j]; mix[j]=rol8(mix[j], round%8u); }
        for (uint j=0;j<32u;j++) sp256[idx+j]=mix[j];
    }
    uchar round2[32];
    { sha256_ctx h; sha256_init(&h); sha256_update_glob(&h, sp256, SP256); sha256_final(&h, round2); }
    uchar anti[32]; anti_asic(round2, sp16, anti);
    { sha3_ctx s3; sha3_init(&s3);
      sha3_update_priv(&s3, round1, 32); sha3_update_priv(&s3, round2, 32);
      sha3_update_priv(&s3, anti, 32);   sha3_update_priv(&s3, hdr, hdr_len);
      sha3_final(&s3, finalh); }
}

// Mining kernel: each work-item tries nonce = base_nonce + gid, patches it into a
// private copy of the header template at byte offset `nonce_off`, hashes, and if
// the hash <= target (big-endian) records the winning nonce.
__kernel void shadowhash_mine(__global const uchar* tmpl, uint hdr_len, uint nonce_off,
                              ulong base_nonce, __global const uchar* target,
                              __global uchar* sp256_all, __global uchar* sp16_all,
                              __global uint* result /* [0]=count, [1]=nonce_lo, [2]=nonce_hi */) {
    uint gid = get_global_id(0);
    ulong nonce = base_nonce + (ulong)gid;

    uchar hdr[512]; // real headers with multiple parents can exceed 256 bytes
    for (uint i=0;i<hdr_len;i++) hdr[i]=tmpl[i];
    for (uint k=0;k<8u;k++) hdr[nonce_off+k]=(uchar)(nonce>>(8u*k));

    __global uchar* sp256 = sp256_all + (ulong)gid*SP256;
    __global uchar* sp16  = sp16_all  + (ulong)gid*SP16;
    uchar finalh[32];
    shadowhash_priv(hdr, hdr_len, sp256, sp16, finalh);

    // hash <= target (big-endian): valid share.
    bool meets = true;
    for (uint i=0;i<32u;i++){ if(finalh[i]<target[i]){meets=true;break;} if(finalh[i]>target[i]){meets=false;break;} }
    if (meets){
        uint slot = atomic_inc(&result[0]);
        if (slot==0){ result[1]=(uint)(nonce & 0xffffffffu); result[2]=(uint)(nonce>>32); }
    }
}
