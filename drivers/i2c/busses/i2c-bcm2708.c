/*
 * Driver for Broadcom BCM2708 BSC Controllers
 *
 * Copyright (C) 2012 Chris Boot & Frank Buss
 *
 * This driver is inspired by:
 * i2c-ocores.c, by Peter Korsgaard <jacmet@sunsite.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/string.h>
#include "xmhfcrypto.h"


/* BSC register offsets */
#define BSC_C			0x00
#define BSC_S			0x04
#define BSC_DLEN		0x08
#define BSC_A			0x0c
#define BSC_FIFO		0x10
#define BSC_DIV			0x14
#define BSC_DEL			0x18
#define BSC_CLKT		0x1c

/* Bitfields in BSC_C */
#define BSC_C_I2CEN		0x00008000
#define BSC_C_INTR		0x00000400
#define BSC_C_INTT		0x00000200
#define BSC_C_INTD		0x00000100
#define BSC_C_ST		0x00000080
#define BSC_C_CLEAR_1		0x00000020
#define BSC_C_CLEAR_2		0x00000010
#define BSC_C_READ		0x00000001

/* Bitfields in BSC_S */
#define BSC_S_CLKT		0x00000200
#define BSC_S_ERR		0x00000100
#define BSC_S_RXF		0x00000080
#define BSC_S_TXE		0x00000040
#define BSC_S_RXD		0x00000020
#define BSC_S_TXD		0x00000010
#define BSC_S_RXR		0x00000008
#define BSC_S_TXW		0x00000004
#define BSC_S_DONE		0x00000002
#define BSC_S_TA		0x00000001

#define I2C_WAIT_LOOP_COUNT	200

#define DRV_NAME		"bcm2708_i2c"

static unsigned int baudrate;
module_param(baudrate, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(baudrate, "The I2C baudrate");

static bool combined = false;
module_param(combined, bool, 0644);
MODULE_PARM_DESC(combined, "Use combined transactions");

struct bcm2708_i2c {
	struct i2c_adapter adapter;

	spinlock_t lock;
	void __iomem *base;
	int irq;
	struct clk *clk;
	u32 cdiv;
	u32 clk_tout;

	struct completion done;

	struct i2c_msg *msg;
	int pos;
	int nmsgs;
	bool error;
};



#define LTC_HMAC_SHA2_BLOCKSIZE 64

/* Various logical functions */
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         RORc((x),(n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))


static inline int sha256_compress(hash_state * md, const unsigned char *buf) {
  uint32_t S[8], W[64], t0, t1;
  int i;

  /* copy state into S */
  for (i = 0; i < 8; i++) {
      S[i] = md->sha256.state[i];
  }

  /* copy the state into 512-bits into W[0..15] */
  for (i = 0; i < 16; i++) {
      LOAD32H(W[i], buf + (4*i));
  }

  /* fill W[16..63] */
  for (i = 16; i < 64; i++) {
      W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
  }

  #define RND(a,b,c,d,e,f,g,h,i,ki)                    \
     t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                  \
     d += t0;                                        \
     h  = t0 + t1;

  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],0,0x428a2f98);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],1,0x71374491);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],2,0xb5c0fbcf);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],3,0xe9b5dba5);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],4,0x3956c25b);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],5,0x59f111f1);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],6,0x923f82a4);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],7,0xab1c5ed5);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],8,0xd807aa98);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],9,0x12835b01);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,0x243185be);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,0x550c7dc3);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,0x72be5d74);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,0x80deb1fe);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,0x9bdc06a7);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,0xc19bf174);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,0xe49b69c1);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,0xefbe4786);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,0x0fc19dc6);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,0x240ca1cc);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,0x2de92c6f);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,0x4a7484aa);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,0x5cb0a9dc);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,0x76f988da);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,0x983e5152);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,0xa831c66d);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,0xb00327c8);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,0xbf597fc7);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,0xc6e00bf3);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,0xd5a79147);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,0x06ca6351);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,0x14292967);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,0x27b70a85);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,0x2e1b2138);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,0x4d2c6dfc);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,0x53380d13);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,0x650a7354);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,0x766a0abb);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,0x81c2c92e);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,0x92722c85);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,0xa2bfe8a1);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,0xa81a664b);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,0xc24b8b70);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,0xc76c51a3);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,0xd192e819);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,0xd6990624);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,0xf40e3585);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,0x106aa070);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,0x19a4c116);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,0x1e376c08);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,0x2748774c);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,0x34b0bcb5);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,0x391c0cb3);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,0x4ed8aa4a);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,0x5b9cca4f);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,0x682e6ff3);
  RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,0x748f82ee);
  RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,0x78a5636f);
  RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,0x84c87814);
  RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,0x8cc70208);
  RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,0x90befffa);
  RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,0xa4506ceb);
  RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,0xbef9a3f7);
  RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,0xc67178f2);

  #undef RND

  /* feedback */
  for (i = 0; i < 8; i++) {
    md->sha256.state[i] = md->sha256.state[i] + S[i];
  }
  return CRYPT_OK;
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
static inline int sha256_init(hash_state * md) {
  LTC_ARGCHK(md != NULL);

  md->sha256.curlen = 0;
  md->sha256.length = 0;
  md->sha256.state[0] = 0x6A09E667UL;
  md->sha256.state[1] = 0xBB67AE85UL;
  md->sha256.state[2] = 0x3C6EF372UL;
  md->sha256.state[3] = 0xA54FF53AUL;
  md->sha256.state[4] = 0x510E527FUL;
  md->sha256.state[5] = 0x9B05688CUL;
  md->sha256.state[6] = 0x1F83D9ABUL;
  md->sha256.state[7] = 0x5BE0CD19UL;
  return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
static inline int sha256_process (hash_state * md, const unsigned char *in,
		    unsigned long inlen) {
  unsigned long n;
  int           err;
  LTC_ARGCHK(md != NULL);
  LTC_ARGCHK(in != NULL);
  if (md->sha256.curlen > sizeof(md->sha256.buf)) {
    return CRYPT_INVALID_ARG;
  }
  if ((md->sha256.length + inlen) < md->sha256.length) {
    return CRYPT_HASH_OVERFLOW;
  }
  while (inlen > 0) {
    if (md->sha256.curlen == 0 && inlen >= 64) {
      if ((err = sha256_compress (md, (unsigned char *)in)) != CRYPT_OK) {
	return err;
      }
      md->sha256.length += 64 * 8;
      in                += 64;
      inlen             -= 64;
    } else {
      n = MIN(inlen, (64 - md-> sha256.curlen));
      XMEMCPY(md->sha256.buf + md->sha256.curlen, in, (size_t)n);
      md->sha256.curlen += n;
      in                += n;
      inlen             -= n;
      if (md->sha256.curlen == 64) {
	if ((err = sha256_compress (md, md->sha256.buf)) != CRYPT_OK) {
	  return err;
	}
	md->sha256.length += 8*64;
	md->sha256.curlen = 0;
      }
    }
  }
  return CRYPT_OK;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return CRYPT_OK if successful
*/
static inline int sha256_done(hash_state * md, unsigned char *out) {
  int i;

  LTC_ARGCHK(md  != NULL);
  LTC_ARGCHK(out != NULL);

  if (md->sha256.curlen >= sizeof(md->sha256.buf)) {
    return CRYPT_INVALID_ARG;
  }

  /* increase the length of the message */
  md->sha256.length += md->sha256.curlen * 8;

  /* append the '1' bit */
  md->sha256.buf[md->sha256.curlen++] = (unsigned char)0x80;

  /* if the length is currently above 56 bytes we append zeros
   * then compress.  Then we can fall back to padding zeros and length
   * encoding like normal.
   */
  if (md->sha256.curlen > 56) {
    while (md->sha256.curlen < 64) {
      md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
    }
    sha256_compress(md, md->sha256.buf);
    md->sha256.curlen = 0;
  }

  /* pad upto 56 bytes of zeroes */
  while (md->sha256.curlen < 56) {
    md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
  }

  /* store length */
  STORE64H(md->sha256.length, md->sha256.buf+56);
  sha256_compress(md, md->sha256.buf);

  /* copy output */
  for (i = 0; i < 8; i++) {
    STORE32H(md->sha256.state[i], out+(4*i));
  }
  return CRYPT_OK;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
static inline int sha256_test(void) {
  static const struct {
    const char *msg;
    unsigned char hash[32];
  } tests[] = {
    { "abc",
      { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad }
    },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 }
    },
  };
  
  int i;
  unsigned char tmp[32];
  hash_state md;

  for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
    sha256_init(&md);
    sha256_process(&md, (unsigned char*)tests[i].msg, (unsigned long)strlen(tests[i].msg));
    sha256_done(&md, tmp);
  }
  return CRYPT_OK;
}

/**
  Hash a block of memory and store the digest.
  @param hash   The index of the hash you wish to use
  @param in     The data you wish to hash
  @param inlen  The length of the data to hash (octets)
  @param out    [out] Where to store the digest
  @param outlen [in/out] Max size and resulting size of the digest
  @return CRYPT_OK if successful
*/
//int hash_memory(int hash, const unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen)
static inline int sha256_memory(const unsigned char *in, unsigned long inlen,
		  unsigned char *out, unsigned long *outlen) {
  hash_state md;
  int err;

  LTC_ARGCHK(in     != NULL);
  LTC_ARGCHK(out    != NULL);
  LTC_ARGCHK(outlen != NULL);

  if (*outlen < 32) {
    *outlen = 32;
    return CRYPT_BUFFER_OVERFLOW;
  }

  if ((err = sha256_init(&md)) != CRYPT_OK) {
    goto LBL_ERR;
  }
  if ((err = sha256_process(&md, in, inlen)) != CRYPT_OK) {
    goto LBL_ERR;
  }
  err = sha256_done(&md, out);
  *outlen = 32;
LBL_ERR:

  return err;
}

/**
  Hash multiple (non-adjacent) blocks of memory at once.
  @param hash   The index of the hash you wish to use
  @param out    [out] Where to store the digest
  @param outlen [in/out] Max size and resulting size of the digest
  @param in     The data you wish to hash
  @param inlen  The length of the data to hash (octets)
  @param ...    tuples of (data,len) pairs to hash, terminated with a (NULL,x) (x=don't care)
  @return CRYPT_OK if successful
*/
static inline int sha256_memory_multi(unsigned char *out, unsigned long *outlen,
                        const unsigned char *in, unsigned long inlen, ...) {
  hash_state           md;
  int                  err;
  va_list              args;
  const unsigned char *curptr;
  unsigned long        curlen;

  LTC_ARGCHK(in     != NULL);
  LTC_ARGCHK(out    != NULL);
  LTC_ARGCHK(outlen != NULL);

  if (*outlen < 32) {
    *outlen = 32;
    return CRYPT_BUFFER_OVERFLOW;
  }

  if ((err = sha256_init(&md)) != CRYPT_OK) {
    goto LBL_ERR;
  }

  va_start(args, inlen);
  curptr = in;
  curlen = inlen;
  for (;;) {
    /* process buf */
    if ((err = sha256_process(&md, curptr, curlen)) != CRYPT_OK) {
      goto LBL_ERR;
    }
    /* step to next */
    curptr = va_arg(args, const unsigned char*);
    if (curptr == NULL) {
      break;
    }
    curlen = va_arg(args, unsigned long);
  }
  err = sha256_done(&md, out);
  *outlen = 32;
LBL_ERR:
    va_end(args);
    return err;
}

/**
   Initialize an HMAC context.
   @param hmac     The HMAC state
   @param hash     The index of the hash you want to use
   @param key      The secret key
   @param keylen   The length of the secret key (octets)
   @return CRYPT_OK if successful
**/
static inline int hmac_sha256_init(hmac_state *hmac, const unsigned char *key, unsigned long keylen) {
    unsigned char buf[LTC_HMAC_SHA2_BLOCKSIZE];
    unsigned long hashsize;
    unsigned long i, z;
    int err;

    LTC_ARGCHK(hmac != NULL);
    LTC_ARGCHK(key  != NULL);

    hmac->hash = 0;
    hashsize   = 32;

    /* valid key length? */
    if (keylen == 0) {
        return CRYPT_INVALID_KEYSIZE;
    }

    /* (1) make sure we have a large enough key */
    if(keylen > LTC_HMAC_SHA2_BLOCKSIZE) {
        z = LTC_HMAC_SHA2_BLOCKSIZE;
        if ((err = sha256_memory(key, keylen, hmac->key, &z)) != CRYPT_OK) {
           goto LBL_ERR;
        }
        keylen = hashsize;
    } else {
        XMEMCPY(hmac->key, key, (size_t)keylen);
    }

    if(keylen < LTC_HMAC_SHA2_BLOCKSIZE) {
    	memset((hmac->key) + keylen, 0, (size_t)(LTC_HMAC_BLOCKSIZE - keylen));
    }

    /* Create the initial vector for step (3) */
    for(i=0; i < LTC_HMAC_SHA2_BLOCKSIZE;   i++) {
       buf[i] = hmac->key[i] ^ 0x36;
    }

    /* Pre-pend that to the hash data */
    if ((err = sha256_init(&hmac->md)) != CRYPT_OK) {
       goto LBL_ERR;
    }

    if ((err = sha256_process(&hmac->md, buf, LTC_HMAC_SHA2_BLOCKSIZE)) != CRYPT_OK) {
       goto LBL_ERR;
    }

    goto done;
LBL_ERR:
done:
   return err;
}


/**
  Process data through HMAC
  @param hmac    The hmac state
  @param in      The data to send through HMAC
  @param inlen   The length of the data to HMAC (octets)
  @return CRYPT_OK if successful
**/
static inline int hmac_sha256_process(hmac_state *hmac, const unsigned char *in, unsigned long inlen) {
    LTC_ARGCHK(hmac != NULL);
    LTC_ARGCHK(in != NULL);
    return sha256_process(&hmac->md, in, inlen);
}


/**
   Terminate an HMAC session
   @param hmac    The HMAC state
   @param out     [out] The destination of the HMAC authentication tag
   @param outlen  [in/out]  The max size and resulting size of the HMAC 
                  authentication tag
   @return CRYPT_OK if successful
**/
static inline int hmac_sha256_done(hmac_state *hmac, unsigned char *out, unsigned long *outlen) {
    unsigned char buf[LTC_HMAC_SHA2_BLOCKSIZE], isha[32];
    unsigned long hashsize, i;
    int err;

    LTC_ARGCHK(hmac  != NULL);
    LTC_ARGCHK(out   != NULL);

    /* get the hash message digest size */
    hashsize = 32;

    /* Get the hash of the first HMAC vector plus the data */
    if ((err = sha256_done(&hmac->md, isha)) != CRYPT_OK) {
       goto LBL_ERR;
    }

    /* Create the second HMAC vector vector for step (3) */
    for(i=0; i < LTC_HMAC_SHA2_BLOCKSIZE; i++) {
        buf[i] = hmac->key[i] ^ 0x5C;
    }

    /* Now calculate the "outer" hash for step (5), (6), and (7) */
    if ((err = sha256_init(&hmac->md)) != CRYPT_OK) { goto LBL_ERR; }
    if ((err = sha256_process(&hmac->md, buf, LTC_HMAC_SHA2_BLOCKSIZE)) != CRYPT_OK) { goto LBL_ERR; }
    if ((err = sha256_process(&hmac->md, isha, hashsize)) != CRYPT_OK) { goto LBL_ERR; }
    if ((err = sha256_done(&hmac->md, buf)) != CRYPT_OK) { goto LBL_ERR; }

    /* copy to output  */
    for (i = 0; i < hashsize && i < *outlen; i++) {
        out[i] = buf[i];
    }
    *outlen = i;

    err = CRYPT_OK;
LBL_ERR:
    return err;
}


/**
   HMAC a block of memory to produce the authentication tag
   @param hash      The index of the hash to use
   @param key       The secret key
   @param keylen    The length of the secret key (octets)
   @param in        The data to HMAC
   @param inlen     The length of the data to HMAC (octets)
   @param out       [out] Destination of the authentication tag
   @param outlen    [in/out] Max size and resulting size of authentication tag
   @return CRYPT_OK if successful
**/
static inline int hmac_sha256_memory(const unsigned char *key,  unsigned long keylen,
                       const unsigned char *in,   unsigned long inlen,
                       unsigned char *out,  unsigned long *outlen) {
    hmac_state hmac;
    int         err;

    LTC_ARGCHK(key    != NULL);
    LTC_ARGCHK(in     != NULL);
    LTC_ARGCHK(out    != NULL);
    LTC_ARGCHK(outlen != NULL);

    if ((err = hmac_sha256_init(&hmac, key, keylen)) != CRYPT_OK) { goto LBL_ERR; }
    if ((err = hmac_sha256_process(&hmac, in, inlen)) != CRYPT_OK) { goto LBL_ERR; }
    if ((err = hmac_sha256_done(&hmac, out, outlen)) != CRYPT_OK) { goto LBL_ERR; }
    err = CRYPT_OK;
LBL_ERR:
   return err;
}

static inline u32 bcm2708_rd(struct bcm2708_i2c *bi, unsigned reg)
{
	printk(KERN_INFO "i2c-bcm2708.c :: bcm2708_rd() called \n");
	return readl(bi->base + reg);
}

static inline void bcm2708_wr(struct bcm2708_i2c *bi, unsigned reg, u32 val)
{
	printk(KERN_INFO "i2c-bcm2708.c :: bcm2708_wr() called \n");
	writel(val, bi->base + reg);
}

static inline void bcm2708_bsc_reset(struct bcm2708_i2c *bi)
{
	bcm2708_wr(bi, BSC_C, 0);
	bcm2708_wr(bi, BSC_S, BSC_S_CLKT | BSC_S_ERR | BSC_S_DONE);
}

static inline void bcm2708_bsc_fifo_drain(struct bcm2708_i2c *bi)
{
	while ((bi->pos < bi->msg->len) && (bcm2708_rd(bi, BSC_S) & BSC_S_RXD))
		bi->msg->buf[bi->pos++] = bcm2708_rd(bi, BSC_FIFO);
}

static inline void bcm2708_bsc_fifo_fill(struct bcm2708_i2c *bi)
{
	while ((bi->pos < bi->msg->len) && (bcm2708_rd(bi, BSC_S) & BSC_S_TXD))
		bcm2708_wr(bi, BSC_FIFO, bi->msg->buf[bi->pos++]);
}

static inline int bcm2708_bsc_setup(struct bcm2708_i2c *bi)
{
	u32 cdiv, s, clk_tout;
	u32 c = BSC_C_I2CEN | BSC_C_INTD | BSC_C_ST | BSC_C_CLEAR_1;
	int wait_loops = I2C_WAIT_LOOP_COUNT;

	printk(KERN_INFO "i2c-bcm2708.c :: bcm2708_bsc_setup() called \n");
	/* Can't call clk_get_rate as it locks a mutex and here we are spinlocked.
	 * Use the value that we cached in the probe.
	 */
	cdiv = bi->cdiv;
	clk_tout = bi->clk_tout;

	if (bi->msg->flags & I2C_M_RD)
		c |= BSC_C_INTR | BSC_C_READ;
	else
		c |= BSC_C_INTT;

	bcm2708_wr(bi, BSC_CLKT, clk_tout);
	bcm2708_wr(bi, BSC_DIV, cdiv);
	bcm2708_wr(bi, BSC_A, bi->msg->addr);
	bcm2708_wr(bi, BSC_DLEN, bi->msg->len);
	if (combined)
	{
		/* Do the next two messages meet combined transaction criteria?
		   - Current message is a write, next message is a read
		   - Both messages to same slave address
		   - Write message can fit inside FIFO (16 bytes or less) */
		if ( (bi->nmsgs > 1) &&
			!(bi->msg[0].flags & I2C_M_RD) && (bi->msg[1].flags & I2C_M_RD) &&
			 (bi->msg[0].addr == bi->msg[1].addr) && (bi->msg[0].len <= 16)) {

			/* Clear FIFO */
			bcm2708_wr(bi, BSC_C, BSC_C_CLEAR_1);

			/* Fill FIFO with entire write message (16 byte FIFO) */
			while (bi->pos < bi->msg->len) {
				bcm2708_wr(bi, BSC_FIFO, bi->msg->buf[bi->pos++]);
			}
			/* Start write transfer (no interrupts, don't clear FIFO) */
			bcm2708_wr(bi, BSC_C, BSC_C_I2CEN | BSC_C_ST);

			/* poll for transfer start bit (should only take 1-20 polls) */
			do {
				s = bcm2708_rd(bi, BSC_S);
			} while (!(s & (BSC_S_TA | BSC_S_ERR | BSC_S_CLKT | BSC_S_DONE)) && --wait_loops >= 0);

			/* did we time out or some error occured? */
			if (wait_loops < 0 || (s & (BSC_S_ERR | BSC_S_CLKT))) {
				return -1;
			}

			/* Send next read message before the write transfer finishes. */
			bi->nmsgs--;
			bi->msg++;
			bi->pos = 0;
			bcm2708_wr(bi, BSC_DLEN, bi->msg->len);
			c = BSC_C_I2CEN | BSC_C_INTD | BSC_C_INTR | BSC_C_ST | BSC_C_READ;
		}
	}
	bcm2708_wr(bi, BSC_C, c);

	return 0;
}

static irqreturn_t bcm2708_i2c_interrupt(int irq, void *dev_id)
{
	struct bcm2708_i2c *bi = dev_id;
	bool handled = true;
	u32 s;
	int ret;

	spin_lock(&bi->lock);

	/* we may see camera interrupts on the "other" I2C channel
		   Just return if we've not sent anything */
	if (!bi->nmsgs || !bi->msg) {
		goto early_exit;
	}

	s = bcm2708_rd(bi, BSC_S);

	if (s & (BSC_S_CLKT | BSC_S_ERR)) {
		bcm2708_bsc_reset(bi);
		bi->error = true;

		bi->msg = 0; /* to inform the that all work is done */
		bi->nmsgs = 0;
		/* wake up our bh */
		complete(&bi->done);
	} else if (s & BSC_S_DONE) {
		bi->nmsgs--;

		if (bi->msg->flags & I2C_M_RD) {
			bcm2708_bsc_fifo_drain(bi);
		}

		bcm2708_bsc_reset(bi);

		if (bi->nmsgs) {
			/* advance to next message */
			bi->msg++;
			bi->pos = 0;
			ret = bcm2708_bsc_setup(bi);
			if (ret < 0) {
				bcm2708_bsc_reset(bi);
				bi->error = true;
				bi->msg = 0; /* to inform the that all work is done */
				bi->nmsgs = 0;
				/* wake up our bh */
				complete(&bi->done);
				goto early_exit;
			}
		} else {
			bi->msg = 0; /* to inform the that all work is done */
			bi->nmsgs = 0;
			/* wake up our bh */
			complete(&bi->done);
		}
	} else if (s & BSC_S_TXW) {
		bcm2708_bsc_fifo_fill(bi);
	} else if (s & BSC_S_RXR) {
		bcm2708_bsc_fifo_drain(bi);
	} else {
		handled = false;
	}

early_exit:
	spin_unlock(&bi->lock);

	return handled ? IRQ_HANDLED : IRQ_NONE;
}

static int bcm2708_i2c_master_xfer(struct i2c_adapter *adap,
	struct i2c_msg *msgs, int num)
{
	struct bcm2708_i2c *bi = adap->algo_data;
	unsigned long flags;
	int ret;

	printk(KERN_INFO "i2c-bcm2708.c :: bcm2708_i2c_master_xfer() called \n");
	spin_lock_irqsave(&bi->lock, flags);

	reinit_completion(&bi->done);
	bi->msg = msgs;
	bi->pos = 0;
	bi->nmsgs = num;
	bi->error = false;

	ret = bcm2708_bsc_setup(bi);

	spin_unlock_irqrestore(&bi->lock, flags);

	/* check the result of the setup */
	if (ret < 0)
	{
		dev_err(&adap->dev, "transfer setup timed out\n");
		goto error_timeout;
	}

	ret = wait_for_completion_timeout(&bi->done, adap->timeout);
	if (ret == 0) {
		dev_err(&adap->dev, "transfer timed out\n");
		goto error_timeout;
	}

	ret = bi->error ? -EIO : num;
	return ret;

error_timeout:
	spin_lock_irqsave(&bi->lock, flags);
	bcm2708_bsc_reset(bi);
	bi->msg = 0; /* to inform the interrupt handler that there's nothing else to be done */
	bi->nmsgs = 0;
	spin_unlock_irqrestore(&bi->lock, flags);
	return -ETIMEDOUT;
}

static u32 bcm2708_i2c_functionality(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | /*I2C_FUNC_10BIT_ADDR |*/ I2C_FUNC_SMBUS_EMUL;
}

static struct i2c_algorithm bcm2708_i2c_algorithm = {
	.master_xfer = bcm2708_i2c_master_xfer,
	.functionality = bcm2708_i2c_functionality,
};

static int bcm2708_i2c_probe(struct platform_device *pdev)
{
	struct resource *regs;
	int irq, err = -ENOMEM;
	struct clk *clk;
	struct bcm2708_i2c *bi;
	struct i2c_adapter *adap;
	unsigned long bus_hz;
	u32 cdiv, clk_tout;
	u32 baud;

	printk(KERN_INFO "i2c-bcm2708.c :: bcm2708_i2c_probe() called \n");

	baud = CONFIG_I2C_BCM2708_BAUDRATE;

	if (pdev->dev.of_node) {
		u32 bus_clk_rate;
		pdev->id = of_alias_get_id(pdev->dev.of_node, "i2c");
		if (pdev->id < 0) {
			dev_err(&pdev->dev, "alias is missing\n");
			return -EINVAL;
		}
		if (!of_property_read_u32(pdev->dev.of_node,
					"clock-frequency", &bus_clk_rate))
			baud = bus_clk_rate;
		else
			dev_warn(&pdev->dev,
				"Could not read clock-frequency property\n");
	}

	if (baudrate)
		baud = baudrate;

	regs = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!regs) {
		dev_err(&pdev->dev, "could not get IO memory\n");
		return -ENXIO;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "could not get IRQ\n");
		return irq;
	}

	clk = clk_get(&pdev->dev, NULL);
	if (IS_ERR(clk)) {
		dev_err(&pdev->dev, "could not find clk: %ld\n", PTR_ERR(clk));
		return PTR_ERR(clk);
	}

	err = clk_prepare_enable(clk);
	if (err) {
		dev_err(&pdev->dev, "could not enable clk: %d\n", err);
		goto out_clk_put;
	}

	bi = kzalloc(sizeof(*bi), GFP_KERNEL);
	if (!bi)
		goto out_clk_disable;

	platform_set_drvdata(pdev, bi);

	adap = &bi->adapter;
	adap->class = I2C_CLASS_HWMON | I2C_CLASS_DDC;
	adap->algo = &bcm2708_i2c_algorithm;
	adap->algo_data = bi;
	adap->dev.parent = &pdev->dev;
	adap->nr = pdev->id;
	strlcpy(adap->name, dev_name(&pdev->dev), sizeof(adap->name));
	adap->dev.of_node = pdev->dev.of_node;

	switch (pdev->id) {
	case 0:
		adap->class = I2C_CLASS_HWMON;
		break;
	case 1:
		adap->class = I2C_CLASS_DDC;
		break;
	case 2:
		adap->class = I2C_CLASS_DDC;
		break;
	default:
		dev_err(&pdev->dev, "can only bind to BSC 0, 1 or 2\n");
		err = -ENXIO;
		goto out_free_bi;
	}

	spin_lock_init(&bi->lock);
	init_completion(&bi->done);

	bi->base = ioremap(regs->start, resource_size(regs));
	if (!bi->base) {
		dev_err(&pdev->dev, "could not remap memory\n");
		goto out_free_bi;
	}

	bi->irq = irq;
	bi->clk = clk;

	err = request_irq(irq, bcm2708_i2c_interrupt, IRQF_SHARED,
			dev_name(&pdev->dev), bi);
	if (err) {
		dev_err(&pdev->dev, "could not request IRQ: %d\n", err);
		goto out_iounmap;
	}

	bcm2708_bsc_reset(bi);

	err = i2c_add_numbered_adapter(adap);
	if (err < 0) {
		dev_err(&pdev->dev, "could not add I2C adapter: %d\n", err);
		goto out_free_irq;
	}

	bus_hz = clk_get_rate(bi->clk);
	cdiv = bus_hz / baud;
	if (cdiv > 0xffff) {
		cdiv = 0xffff;
		baud = bus_hz / cdiv;
	}

	clk_tout = 35/1000*baud; //35ms timeout as per SMBus specs.
	if (clk_tout > 0xffff)
		clk_tout = 0xffff;
	
	bi->cdiv = cdiv;
	bi->clk_tout = clk_tout;

	dev_info(&pdev->dev, "BSC%d Controller at 0x%08lx (irq %d) (baudrate %d)\n",
		pdev->id, (unsigned long)regs->start, irq, baud);

	return 0;

out_free_irq:
	free_irq(bi->irq, bi);
out_iounmap:
	iounmap(bi->base);
out_free_bi:
	kfree(bi);
out_clk_disable:
	clk_disable_unprepare(clk);
out_clk_put:
	clk_put(clk);
	return err;
}

static int bcm2708_i2c_remove(struct platform_device *pdev)
{
	struct bcm2708_i2c *bi = platform_get_drvdata(pdev);

	platform_set_drvdata(pdev, NULL);

	i2c_del_adapter(&bi->adapter);
	free_irq(bi->irq, bi);
	iounmap(bi->base);
	clk_disable_unprepare(bi->clk);
	clk_put(bi->clk);
	kfree(bi);

	return 0;
}

static const struct of_device_id bcm2708_i2c_of_match[] = {
        { .compatible = "brcm,bcm2708-i2c" },
        {},
};
MODULE_DEVICE_TABLE(of, bcm2708_i2c_of_match);

static struct platform_driver bcm2708_i2c_driver = {
	.driver		= {
		.name	= DRV_NAME,
		.owner	= THIS_MODULE,
		.of_match_table = bcm2708_i2c_of_match,
	},
	.probe		= bcm2708_i2c_probe,
	.remove		= bcm2708_i2c_remove,
};

// module_platform_driver(bcm2708_i2c_driver);


static int __init bcm2708_i2c_init(void)
{
	return platform_driver_register(&bcm2708_i2c_driver);
}

static void __exit bcm2708_i2c_exit(void)
{
	platform_driver_unregister(&bcm2708_i2c_driver);
}

module_init(bcm2708_i2c_init);
module_exit(bcm2708_i2c_exit);



MODULE_DESCRIPTION("BSC controller driver for Broadcom BCM2708");
MODULE_AUTHOR("Chris Boot <bootc@bootc.net>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" DRV_NAME);
