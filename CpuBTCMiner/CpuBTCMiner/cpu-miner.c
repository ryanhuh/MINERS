
/*
 * Copyright 2010 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#ifndef WIN32
#include <sys/resource.h>
#endif
#include <getopt.h>
#include <jansson.h>
#include <curl/curl.h>
#include "compat.h"
#include "miner.h"

#define PROGRAM_NAME		"minerd"
#define DEF_RPC_URL		"http://127.0.0.1:8332/"
#define DEF_RPC_USERNAME	"rpcuser"
#define DEF_RPC_PASSWORD	"rpcpass"
#define DEF_RPC_USERPASS	DEF_RPC_USERNAME ":" DEF_RPC_PASSWORD

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>
static inline void drop_policy(void)
{
	struct sched_param param;

#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

static inline void affine_to_cpu(int id, int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(&set), &set);
	applog(LOG_INFO, "Binding thread %d to cpu %d", id, cpu);
}
#else
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
}
#endif
		
enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands	cmd;
	struct thr_info		*thr;
	union {
		struct work	*work;
	} u;
};

enum sha256_algos {
	ALGO_C,			/* plain C */
	ALGO_4WAY,		/* parallel SSE2 */
	ALGO_VIA,		/* VIA padlock */
	ALGO_CRYPTOPP,		/* Crypto++ (C) */
	ALGO_CRYPTOPP_ASM32,	/* Crypto++ 32-bit assembly */
	ALGO_SSE2_64,		/* SSE2 for x86_64 */
};
/*
static const char *algo_names[] = {
	[ALGO_C]		= "c",
#ifdef WANT_SSE2_4WAY
	[ALGO_4WAY]		= "4way",
#endif
#ifdef WANT_VIA_PADLOCK
	[ALGO_VIA]		= "via",
#endif
	[ALGO_CRYPTOPP]		= "cryptopp",
#ifdef WANT_CRYPTOPP_ASM32
	[ALGO_CRYPTOPP_ASM32]	= "cryptopp_asm32",
#endif
#ifdef WANT_X8664_SSE2
	[ALGO_SSE2_64]		= "sse2_64",
#endif
};
*/
enum algos {
    ALGO_SCRYPT,        /* scrypt(1024,1,1) */
    ALGO_SHA256D,        /* SHA-256d */
};

static const char *algo_names[] = {
    [ALGO_SCRYPT]        = "scrypt",
    [ALGO_SHA256D]        = "sha256d",
};

bool opt_debug = false;
bool opt_protocol = false;
bool want_longpoll = true;
bool have_longpoll = false;
bool use_syslog = false;
static bool opt_quiet = false;
#if 0
static int opt_retries = 10;
static int opt_fail_pause = 30;
#else
static int opt_retries = 5;
static int opt_fail_pause = 10;
#endif
int opt_scantime = 5;
static json_t *opt_config;
static const bool opt_time = true;
#ifdef WANT_X8664_SSE2
static enum sha256_algos opt_algo = ALGO_SSE2_64;
#else
static enum sha256_algos opt_algo = ALGO_C;
#endif
static int opt_n_threads;
static int num_processors;
static char *rpc_url;
static char *rpc_userpass;
static char *rpc_user, *rpc_pass;
struct thr_info *thr_info;
static int work_thr_id;
int longpoll_thr_id;
struct work_restart *work_restart = NULL;
pthread_mutex_t time_lock;

static bool opt_benchmark = false;
static int opt_scrypt_n = 1024;
pthread_mutex_t applog_lock;

#define LP_SCANTIME        60
static struct work g_work;
static time_t g_work_time;
static pthread_mutex_t g_work_lock;
static bool submit_old = false;
static char *lp_id;

bool have_stratum = false;
static double *thr_hashrates;

static pthread_mutex_t stats_lock;

static unsigned long accepted_count = 0L;
static unsigned long rejected_count = 0L;

static int pk_script_size;
bool allow_getwork = true;
static unsigned char pk_script[25];
static char coinbase_sig[101] = "";

//비교 데이타
static uint32_t _blockCurTime = 0;

struct option_help {
	const char	*name;
	const char	*helptext;
};

static struct option_help options_help[] = {
	{ "help",
	  "(-h) Display this help text" },

	{ "config FILE",
	  "(-c FILE) JSON-format configuration file (default: none)\n"
	  "See example-cfg.json for an example configuration." },

	{ "algo XXX",
	  "(-a XXX) Specify sha256 implementation:\n"
	  "\tc\t\tLinux kernel sha256, implemented in C (default)"
#ifdef WANT_SSE2_4WAY
	  "\n\t4way\t\ttcatm's 4-way SSE2 implementation"
#endif
#ifdef WANT_VIA_PADLOCK
	  "\n\tvia\t\tVIA padlock implementation"
#endif
	  "\n\tcryptopp\tCrypto++ C/C++ implementation"
#ifdef WANT_CRYPTOPP_ASM32
	  "\n\tcryptopp_asm32\tCrypto++ 32-bit assembler implementation"
#endif
#ifdef WANT_X8664_SSE2
	  "\n\tsse2_64\t\tSSE2 implementation for x86_64 machines"
#endif
	  },

	{ "quiet",
	  "(-q) Disable per-thread hashmeter output (default: off)" },

	{ "debug",
	  "(-D) Enable debug output (default: off)" },

	{ "no-longpoll",
	  "Disable X-Long-Polling support (default: enabled)" },

	{ "protocol-dump",
	  "(-P) Verbose dump of protocol-level activities (default: off)" },

	{ "retries N",
	  "(-r N) Number of times to retry, if JSON-RPC call fails\n"
	  "\t(default: 10; use -1 for \"never\")" },

	{ "retry-pause N",
	  "(-R N) Number of seconds to pause, between retries\n"
	  "\t(default: 30)" },

	{ "scantime N",
	  "(-s N) Upper bound on time spent scanning current work,\n"
	  "\tin seconds. (default: 5)" },

#ifdef HAVE_SYSLOG_H
	{ "syslog",
	  "Use system log for output messages (default: standard error)" },
#endif

	{ "threads N",
	  "(-t N) Number of miner threads (default: 1)" },

	{ "url URL",
	  "URL for bitcoin JSON-RPC server "
	  "(default: " DEF_RPC_URL ")" },

	{ "userpass USERNAME:PASSWORD",
	  "Username:Password pair for bitcoin JSON-RPC server "
	  "(default: " DEF_RPC_USERPASS ")" },

	{ "user USERNAME",
	  "(-u USERNAME) Username for bitcoin JSON-RPC server "
	  "(default: " DEF_RPC_USERNAME ")" },

	{ "pass PASSWORD",
	  "(-p PASSWORD) Password for bitcoin JSON-RPC server "
	  "(default: " DEF_RPC_PASSWORD ")" },
};

static struct option options[] = {
	{ "algo", 1, NULL, 'a' },
	{ "config", 1, NULL, 'c' },
	{ "debug", 0, NULL, 'D' },
	{ "help", 0, NULL, 'h' },
	{ "no-longpoll", 0, NULL, 1003 },
	{ "pass", 1, NULL, 'p' },
	{ "protocol-dump", 0, NULL, 'P' },
	{ "quiet", 0, NULL, 'q' },
	{ "threads", 1, NULL, 't' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "scantime", 1, NULL, 's' },
#ifdef HAVE_SYSLOG_H
	{ "syslog", 0, NULL, 1004 },
#endif
	{ "url", 1, NULL, 1001 },
	{ "user", 1, NULL, 'u' },
    { "userpass", 1, NULL, 1002 },
    { "address", 1, NULL, 'd' },
	{ }
};

struct work {
#if 0
	unsigned char	data[128];
	unsigned char	hash1[64];
	unsigned char	midstate[32];
	unsigned char	target[32];

	unsigned char	hash[32];
#else
    uint32_t data[32];
    uint32_t target[8];
    
    int height;
    char *txs;
    char *workid;
    
    char *job_id;
    size_t xnonce2_len;
    unsigned char *xnonce2;
#endif
};

static inline void work_free(struct work *w)
{
    free(w->txs);
    free(w->workid);
    free(w->job_id);
    free(w->xnonce2);
}

static inline void work_copy(struct work *dest, const struct work *src)
{
    memcpy(dest, src, sizeof(struct work));
    if (src->txs)
        dest->txs = strdup(src->txs);
    if (src->workid)
        dest->workid = strdup(src->workid);
    if (src->job_id)
        dest->job_id = strdup(src->job_id);
    if (src->xnonce2) {
        dest->xnonce2 = malloc(src->xnonce2_len);
        memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
    }
}

static void share_result(int result, const char *reason)
{
    char s[345];
    double hashrate;
    int i;
    
    hashrate = 0.;
    pthread_mutex_lock(&stats_lock);
    for (i = 0; i < opt_n_threads; i++)
        hashrate += thr_hashrates[i];
    result ? accepted_count++ : rejected_count++;
    pthread_mutex_unlock(&stats_lock);
    
    sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", 1e-3 * hashrate);
    applog(LOG_INFO, "accepted: %lu/%lu (%.2f%%), %s khash/s %s",
           accepted_count,
           accepted_count + rejected_count,
           100. * accepted_count / (accepted_count + rejected_count),
           s,
           result ? "(yay!!!)" : "(booooo)");
    
    if (opt_debug && reason)
        applog(LOG_DEBUG, "DEBUG: reject reason: %s", reason);
}

static bool jobj_binary(const json_t *obj, const char *key,
			void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin(buf, hexstr, buflen))
		return false;

	return true;
}

static bool gbt_work_decode(const json_t *val, struct work *work)
{
    int i, n;
    uint32_t version, curtime, bits;
    uint32_t prevhash[8];
    uint32_t target[8];
    int cbtx_size;
    unsigned char *cbtx = NULL;
    int tx_count, tx_size;
    unsigned char txc_vi[9];
    unsigned char (*merkle_tree)[32] = NULL;
    bool coinbase_append = false;
    bool submit_coinbase = false;
    bool segwit = false;
    json_t *tmp, *txa;
    bool rc = false;
    
    tmp = json_object_get(val, "rules");
    if (tmp && json_is_array(tmp)) {
        n = json_array_size(tmp);
        for (i = 0; i < n; i++) {
            const char *s = json_string_value(json_array_get(tmp, i));
            if (!s)
                continue;
            if (!strcmp(s, "segwit") || !strcmp(s, "!segwit"))
                segwit = true;
        }
    }
    
    applog(DEBUG,"json=%s",json_dumps(val, JSON_INDENT(0))
           );
    
    tmp = json_object_get(val, "mutable");
    if (tmp && json_is_array(tmp)) {
        n = json_array_size(tmp);
        for (i = 0; i < n; i++) {
            const char *s = json_string_value(json_array_get(tmp, i));
            if (!s)
                continue;
            if (!strcmp(s, "coinbase/append"))
                coinbase_append = true;
            else if (!strcmp(s, "submit/coinbase"))
                submit_coinbase = true;
        }
    }
    
    tmp = json_object_get(val, "height");
#if 0// it was pass by float.
    if (!tmp || !json_is_integer(tmp)) {
        applog(LOG_ERR, "JSON invalid height");
        goto out;
    }
    work->height = json_integer_value(tmp);
#else
    if(!tmp || !json_is_real(tmp)){
            applog(LOG_ERR, "JSON invalid height");
            goto out;
    }
    work->height = (int)json_real_value(tmp);
#endif
    
#if 0
    tmp = json_object_get(val, "version");
    if (!tmp || !json_is_integer(tmp)) {
        applog(LOG_ERR, "JSON invalid version");
        goto out;
    }
    version = json_integer_value(tmp);
#else
    tmp = json_object_get(val, "version");
    if (!tmp || !json_is_real(tmp)) {
        applog(LOG_ERR, "JSON invalid version");
        goto out;
    }
    version = (int)json_real_value(tmp);

#endif
    
    if (unlikely(!jobj_binary(val, "previousblockhash", prevhash, sizeof(prevhash)))) {
        applog(LOG_ERR, "JSON invalid previousblockhash");
        goto out;
    }
#if 0
    tmp = json_object_get(val, "curtime");
    if (!tmp || !json_is_integer(tmp)) {
        applog(LOG_ERR, "JSON invalid curtime");
        goto out;
    }
    curtime = json_integer_value(tmp);
#else
    tmp = json_object_get(val, "curtime");
    if (!tmp || !json_is_real(tmp)) {
        applog(LOG_ERR, "JSON invalid curtime");
        goto out;
    }
    curtime = (int)json_real_value(tmp);
    _blockCurTime = curtime;
#endif
    if (unlikely(!jobj_binary(val, "bits", &bits, sizeof(bits)))) {
        applog(LOG_ERR, "JSON invalid bits");
        goto out;
    }
#if 1
    tmp = json_object_get(val, "mintime");
    if (!tmp || !json_is_real(tmp)) {
        applog(LOG_ERR, "JSON invalid mintime");
    }
    else
    {
        _blockCurTime = (int)json_real_value(tmp);
    }
#endif
    
    
    /* find count and size of transactions */
    txa = json_object_get(val, "transactions");
    if (!txa || !json_is_array(txa)) {
        applog(LOG_ERR, "JSON invalid transactions");
        goto out;
    }
    tx_count = json_array_size(txa);
    tx_size = 0;
    for (i = 0; i < tx_count; i++) {
        const json_t *tx = json_array_get(txa, i);
        const char *tx_hex = json_string_value(json_object_get(tx, "data"));
        if (!tx_hex) {
            applog(LOG_ERR, "JSON invalid transactions");
            goto out;
        }
        tx_size += strlen(tx_hex) / 2;
    }
    
    /* build coinbase transaction */
    tmp = json_object_get(val, "coinbasetxn");
    if (tmp) {
        const char *cbtx_hex = json_string_value(json_object_get(tmp, "data"));
        cbtx_size = cbtx_hex ? strlen(cbtx_hex) / 2 : 0;
        cbtx = malloc(cbtx_size + 100);
        if (cbtx_size < 60 || !hex2bin(cbtx, cbtx_hex, cbtx_size)) {
            applog(LOG_ERR, "JSON invalid coinbasetxn");
            goto out;
        }
    } else {
        int64_t cbvalue;
        if (!pk_script_size) {
            if (allow_getwork) {
                applog(LOG_INFO, "No payout address provided, switching to getwork");
            } else
                applog(LOG_ERR, "No payout address provided");
            goto out;
        }
#if 1
        tmp = json_object_get(val, "coinbasevalue");
        if (!tmp || !json_is_number(tmp)) {
            applog(LOG_ERR, "JSON invalid coinbasevalue");
            goto out;
        }
        cbvalue = json_is_integer(tmp) ? json_integer_value(tmp) : json_number_value(tmp);
#else
        tmp = json_object_get(val, "coinbasevalue");
        if (!tmp || !json_is_real(tmp)) {
            applog(LOG_ERR, "JSON invalid coinbasevalue");
            goto out;
        }
        cbvalue = json_is_real(tmp) ? (int)json_real_value(tmp) : json_number_value(tmp);

#endif
        cbtx = malloc(256);
        le32enc((uint32_t *)cbtx, 1); /* version */
        cbtx[4] = 1; /* in-counter */
        memset(cbtx+5, 0x00, 32); /* prev txout hash */
        le32enc((uint32_t *)(cbtx+37), 0xffffffff); /* prev txout index */
        cbtx_size = 43;
        /* BIP 34: height in coinbase */
        for (n = work->height; n; n >>= 8) {
            cbtx[cbtx_size++] = n & 0xff;
            if (n < 0x100 && n >= 0x80)
                cbtx[cbtx_size++] = 0;
        }
        cbtx[42] = cbtx_size - 43;
        cbtx[41] = cbtx_size - 42; /* scriptsig length */
        le32enc((uint32_t *)(cbtx+cbtx_size), 0xffffffff); /* sequence */
        cbtx_size += 4;
        cbtx[cbtx_size++] = segwit ? 2 : 1; /* out-counter */
        le32enc((uint32_t *)(cbtx+cbtx_size), (uint32_t)cbvalue); /* value */
        le32enc((uint32_t *)(cbtx+cbtx_size+4), cbvalue >> 32);
        cbtx_size += 8;
        cbtx[cbtx_size++] = pk_script_size; /* txout-script length */
        memcpy(cbtx+cbtx_size, pk_script, pk_script_size);
        cbtx_size += pk_script_size;
        if (segwit) {
            unsigned char (*wtree)[32] = calloc(tx_count + 2, 32);
            memset(cbtx+cbtx_size, 0, 8); /* value */
            cbtx_size += 8;
            cbtx[cbtx_size++] = 38; /* txout-script length */
            cbtx[cbtx_size++] = 0x6a; /* txout-script */
            cbtx[cbtx_size++] = 0x24;
            cbtx[cbtx_size++] = 0xaa;
            cbtx[cbtx_size++] = 0x21;
            cbtx[cbtx_size++] = 0xa9;
            cbtx[cbtx_size++] = 0xed;
            for (i = 0; i < tx_count; i++) {
                const json_t *tx = json_array_get(txa, i);
                const json_t *hash = json_object_get(tx, "hash");
                if (!hash || !hex2bin(wtree[1+i], json_string_value(hash), 32)) {
                    applog(LOG_ERR, "JSON invalid transaction hash");
                    free(wtree);
                    goto out;
                }
                memrev(wtree[1+i], 32);
            }
            n = tx_count + 1;
            while (n > 1) {
                if (n % 2)
                    memcpy(wtree[n], wtree[n-1], 32);
                n = (n + 1) / 2;
                for (i = 0; i < n; i++)
                    sha256d(wtree[i], wtree[2*i], 64);
            }
            memset(wtree[1], 0, 32);  /* witness reserved value = 0 */
            sha256d(cbtx+cbtx_size, wtree[0], 64);
            cbtx_size += 32;
            free(wtree);
        }
        le32enc((uint32_t *)(cbtx+cbtx_size), 0); /* lock time */
        cbtx_size += 4;
        coinbase_append = true;
    }
    if (coinbase_append) {
        unsigned char xsig[100];
        int xsig_len = 0;
        if (*coinbase_sig) {
            n = strlen(coinbase_sig);
            if (cbtx[41] + xsig_len + n <= 100) {
                memcpy(xsig+xsig_len, coinbase_sig, n);
                xsig_len += n;
            } else {
                applog(LOG_WARNING, "Signature does not fit in coinbase, skipping");
            }
        }
        tmp = json_object_get(val, "coinbaseaux");
        if (tmp && json_is_object(tmp)) {
            void *iter = json_object_iter(tmp);
            while (iter) {
                unsigned char buf[100];
                const char *s = json_string_value(json_object_iter_value(iter));
                n = s ? strlen(s) / 2 : 0;
                if (!s || n > 100 || !hex2bin(buf, s, n)) {
                    applog(LOG_ERR, "JSON invalid coinbaseaux");
                    break;
                }
                if (cbtx[41] + xsig_len + n <= 100) {
                    memcpy(xsig+xsig_len, buf, n);
                    xsig_len += n;
                }
                iter = json_object_iter_next(tmp, iter);
            }
        }
        if (xsig_len) {
            unsigned char *ssig_end = cbtx + 42 + cbtx[41];
            int push_len = cbtx[41] + xsig_len < 76 ? 1 :
            cbtx[41] + 2 + xsig_len > 100 ? 0 : 2;
            n = xsig_len + push_len;
            memmove(ssig_end + n, ssig_end, cbtx_size - 42 - cbtx[41]);
            cbtx[41] += n;
            if (push_len == 2)
                *(ssig_end++) = 0x4c; /* OP_PUSHDATA1 */
            if (push_len)
                *(ssig_end++) = xsig_len;
            memcpy(ssig_end, xsig, xsig_len);
            cbtx_size += n;
        }
    }
    
    n = varint_encode(txc_vi, 1 + tx_count);
    work->txs = malloc(2 * (n + cbtx_size + tx_size) + 1);
    bin2hex(work->txs, txc_vi, n);
    bin2hex(work->txs + 2*n, cbtx, cbtx_size);
    
    /* generate merkle root */
    merkle_tree = malloc(32 * ((1 + tx_count + 1) & ~1));
    sha256d(merkle_tree[0], cbtx, cbtx_size);
    for (i = 0; i < tx_count; i++) {
        tmp = json_array_get(txa, i);
        const char *tx_hex = json_string_value(json_object_get(tmp, "data"));
        const int tx_size = tx_hex ? strlen(tx_hex) / 2 : 0;
        if (segwit) {
            const char *txid = json_string_value(json_object_get(tmp, "txid"));
            if (!txid || !hex2bin(merkle_tree[1 + i], txid, 32)) {
                applog(LOG_ERR, "JSON invalid transaction txid");
                goto out;
            }
            memrev(merkle_tree[1 + i], 32);
        } else {
            unsigned char *tx = malloc(tx_size);
            if (!tx_hex || !hex2bin(tx, tx_hex, tx_size)) {
                applog(LOG_ERR, "JSON invalid transactions");
                free(tx);
                goto out;
            }
            sha256d(merkle_tree[1 + i], tx, tx_size);
            free(tx);
        }
        if (!submit_coinbase)
            strcat(work->txs, tx_hex);
    }
    n = 1 + tx_count;
    while (n > 1) {
        if (n % 2) {
            memcpy(merkle_tree[n], merkle_tree[n-1], 32);
            ++n;
        }
        n /= 2;
        for (i = 0; i < n; i++)
            sha256d(merkle_tree[i], merkle_tree[2*i], 64);
    }
    
    /* assemble block header */
    work->data[0] = swab32(version);
    for (i = 0; i < 8; i++)
        work->data[8 - i] = le32dec(prevhash + i);
    for (i = 0; i < 8; i++)
        work->data[9 + i] = be32dec((uint32_t *)merkle_tree[0] + i);
    work->data[17] = swab32(curtime);
    work->data[18] = le32dec(&bits);
    memset(work->data + 19, 0x00, 52);
    work->data[20] = 0x80000000;
    work->data[31] = 0x00000280;
    // make from nBits,
    // 1. arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
    // 2. result.pushKV("target", hashTarget.GetHex());
    if (unlikely(!jobj_binary(val, "target", target, sizeof(target)))) {
        applog(LOG_ERR, "JSON invalid target");
        goto out;
    }
    for (i = 0; i < ARRAY_SIZE(work->target); i++)
        work->target[7 - i] = be32dec(target + i);
    
    tmp = json_object_get(val, "workid");
    if (tmp) {
        if (!json_is_string(tmp)) {
            applog(LOG_ERR, "JSON invalid workid");
            goto out;
        }
        work->workid = strdup(json_string_value(tmp));
    }
    
    /* Long polling */
    tmp = json_object_get(val, "longpollid");
    if (want_longpoll && json_is_string(tmp)) {
        free(lp_id);
        lp_id = strdup(json_string_value(tmp));
        if (!have_longpoll) {
            char *lp_uri;
            tmp = json_object_get(val, "longpolluri");
            lp_uri = strdup(json_is_string(tmp) ? json_string_value(tmp) : rpc_url);
            have_longpoll = true;
            tq_push(thr_info[longpoll_thr_id].q, lp_uri);
        }
    }
    
    rc = true;
    
out:
    free(cbtx);
    free(merkle_tree);
    return rc;
}



static bool work_decode(const json_t *val, struct work *work)
{
#if 0
	if (unlikely(!jobj_binary(val, "midstate",
			 work->midstate, sizeof(work->midstate)))) {
		applog(LOG_ERR, "JSON inval midstate");
		goto err_out;
	}

	if (unlikely(!jobj_binary(val, "data", work->data, sizeof(work->data)))) {
		applog(LOG_ERR, "JSON inval data");
		goto err_out;
	}

	if (unlikely(!jobj_binary(val, "hash1", work->hash1, sizeof(work->hash1)))) {
		applog(LOG_ERR, "JSON inval hash1");
		goto err_out;
	}

	if (unlikely(!jobj_binary(val, "target", work->target, sizeof(work->target)))) {
		applog(LOG_ERR, "JSON inval target");
		goto err_out;
	}
    memset(work->hash, 0, sizeof(work->hash));
#else
    if (unlikely(!jobj_binary(val, "data", work->data, sizeof(work->data)))) {
        applog(LOG_ERR, "JSON inval data");
        goto err_out;
    }
    if (unlikely(!jobj_binary(val, "target", work->target, sizeof(work->target)))) {
        applog(LOG_ERR, "JSON inval target");
        goto err_out;
    }

    for(int n=0;n<ARRAY_SIZE(work->data);n++)
    {
        work->data[n] = le32dec(work->data + n);
    }
    for(int n=0;n<ARRAY_SIZE(work->target);n++)
        work->target[n] = le32dec(work->target +n);
    
#endif

	return true;

err_out:
	return false;
}

static bool submit_upstream_work(CURL *curl, const struct work *work)
{
	char *hexstr = NULL;
	json_t *val, *res;
	char s[345];
	bool rc = false;
    char data_str[2 * sizeof(work->data) + 1];
    int i = 0;
    
	/* build hex string */
    if (work->txs) {
        char *req;
        
        for (i = 0; i < ARRAY_SIZE(work->data); i++)
            be32enc(work->data + i, work->data[i]);
        bin2hex(data_str, (unsigned char *)work->data, 80);
        if (work->workid) {
            char *params;
            val = json_object();
            json_object_set_new(val, "workid", json_string(work->workid));
            params = json_dumps(val, 0);
            json_decref(val);
            req = malloc(128 + 2*80 + strlen(work->txs) + strlen(params));
            sprintf(req,
                    "{\"method\": \"submitblock\", \"params\": [\"%s%s\", %s], \"id\":1}\r\n",
                    data_str, work->txs, params);
            free(params);
        } else {
            req = malloc(128 + 2*80 + strlen(work->txs));
            sprintf(req,
                    "{\"method\": \"submitblock\", \"params\": [\"%s%s\"], \"id\":1}\r\n",
                    data_str, work->txs);
        }
        val = json_rpc_call(curl, rpc_url, rpc_userpass, req, NULL, 0);
        free(req);
        if (unlikely(!val)) {
            applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
            goto out;
        }
        
        res = json_object_get(val, "result");
        if (json_is_object(res)) {
            char *res_str;
            bool sumres = false;
            void *iter = json_object_iter(res);
            while (iter) {
                if (json_is_null(json_object_iter_value(iter))) {
                    sumres = true;
                    break;
                }
                iter = json_object_iter_next(res, iter);
            }
            res_str = json_dumps(res, 0);
            share_result(sumres, res_str);
            free(res_str);
        } else
            share_result(json_is_null(res), json_string_value(res));
        
        json_decref(val);
    }

	rc = true;

out:
	free(hexstr);
	return rc;
}
#if 0
static const char *rpc_req =
	"{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";
#else

#if 1 // pool
static const char *rpc_req =
"{\"method\": \"getblocktemplate\", \"params\": [{  \"capabilities\":  [\"coinbasetxn\",\"workid\", \"coinbase/append\"]}]}\r\n";
#else
#define GBT_CAPABILITIES "[\"coinbasetxn\", \"coinbasevalue\", \"longpoll\", \"workid\"]"
#define GBT_RULES "[\"segwit\"]"

static const char *rpc_req =
"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
GBT_CAPABILITIES ", \"rules\": " GBT_RULES "}], \"id\":0}\r\n";

#endif
#endif

static bool get_upstream_work(CURL *curl, struct work *work)
{
	json_t *val;
	bool rc;

	val = json_rpc_call(curl, rpc_url, rpc_userpass, rpc_req,
			    want_longpoll, false);
	if (!val)
		return false;

#if 0
    rc = work_decode(json_object_get(val, "result"), work);
#else
    rc = gbt_work_decode(json_object_get(val,"result"),work);
#endif
	json_decref(val);

	return rc;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc));	/* poison */
	free(wc);
}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl)
{
	struct work *ret_work;
	int failures = 0;

	ret_work = calloc(1, sizeof(*ret_work));
	if (!ret_work)
		return false;

	/* obtain new work from bitcoin via JSON-RPC */
	while (!get_upstream_work(curl, ret_work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
			free(ret_work);
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "json_rpc_call failed, retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}

	/* send work to requesting thread */
	if (!tq_push(wc->thr->q, ret_work))
		free(ret_work);

	return true;
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
	int failures = 0;

	/* submit solution to bitcoin via JSON-RPC */
	while (!submit_upstream_work(curl, wc->u.work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "...retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}

	return true;
}

static void *workio_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}

	while (ok) {
		struct workio_cmd *wc;

		/* wait for workio_cmd sent to us, on our queue */
		wc = tq_pop(mythr->q, NULL);
		if (!wc) {
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd) {
		case WC_GET_WORK:
			ok = workio_get_work(wc, curl);
			break;
		case WC_SUBMIT_WORK:
			ok = workio_submit_work(wc, curl);
			break;

		default:		/* should never happen */
			ok = false;
			break;
		}

		workio_cmd_free(wc);
	}

	tq_freeze(mythr->q);
	curl_easy_cleanup(curl);

	return NULL;
}

static void hashmeter(int thr_id, const struct timeval *diff,
		      unsigned long hashes_done)
{
	double khashes, secs;

	khashes = hashes_done / 1000.0;
	secs = (double)diff->tv_sec + ((double)diff->tv_usec / 1000000.0);

	if (!opt_quiet)
		applog(LOG_INFO, "thread %d: %lu hashes, %.2f khash/sec",
		       thr_id, hashes_done,
		       khashes / secs);
}

static bool get_work(struct thr_info *thr, struct work *work)
{
	struct workio_cmd *wc;
	struct work *work_heap;

	/* fill out work request message */
	wc = calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->cmd = WC_GET_WORK;
	wc->thr = thr;

	/* send work request to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc)) {
		workio_cmd_free(wc);
		return false;
	}

	/* wait for response, a unit of work */
	work_heap = tq_pop(thr->q, NULL);
	if (!work_heap)
		return false;

	/* copy returned work into storage provided by caller */
	memcpy(work, work_heap, sizeof(*work));
	free(work_heap);

	return true;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
	struct workio_cmd *wc;

	/* fill out work request message */
	wc = calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->u.work = malloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;

	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	memcpy(wc->u.work, work_in, sizeof(*work_in));

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;

	return true;

err_out:
	workio_cmd_free(wc);
	return false;
}
#if 0
static void *miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	int thr_id = mythr->id;
	uint32_t max_nonce = 0xffffff;

	/* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
	 * and if that fails, then SCHED_BATCH. No need for this to be an
	 * error if it fails */
	setpriority(PRIO_PROCESS, 0, 19);
	drop_policy();

	/* Cpu affinity only makes sense if the number of threads is a multiple
	 * of the number of CPUs */
	if (!(opt_n_threads % num_processors))
		affine_to_cpu(mythr->id, mythr->id % num_processors);

	while (1) {
		struct work work __attribute__((aligned(128)));
		unsigned long hashes_done;
		struct timeval tv_start, tv_end, diff;
		uint64_t max64;
		bool rc;

		/* obtain new work from internal workio thread */
		if (unlikely(!get_work(mythr, &work))) {
			applog(LOG_ERR, "work retrieval failed, exiting "
				"mining thread %d", mythr->id);
			goto out;
		}

		hashes_done = 0;
		gettimeofday(&tv_start, NULL);

		/* scan nonces for a proof-of-work hash */
		switch (opt_algo) {
		case ALGO_C:
			rc = scanhash_c(thr_id, work.midstate, work.data + 64,
				        work.hash, work.target,
					max_nonce, &hashes_done);
			break;

#ifdef WANT_X8664_SSE2
		case ALGO_SSE2_64: {
			unsigned int rc5 =
			        scanhash_sse2_64(thr_id, work.midstate, work.data + 64,
						 work.hash1, work.hash,
						 work.target,
					         max_nonce, &hashes_done);
			rc = (rc5 == -1) ? false : true;
			}
			break;
#endif

#ifdef WANT_SSE2_4WAY
		case ALGO_4WAY: {
			unsigned int rc4 =
				ScanHash_4WaySSE2(thr_id, work.midstate, work.data + 64,
						  work.hash1, work.hash,
						  work.target,
						  max_nonce, &hashes_done);
			rc = (rc4 == -1) ? false : true;
			}
			break;
#endif

#ifdef WANT_VIA_PADLOCK
		case ALGO_VIA:
			rc = scanhash_via(thr_id, work.data, work.target,
					  max_nonce, &hashes_done);
			break;
#endif
		case ALGO_CRYPTOPP:
			rc = scanhash_cryptopp(thr_id, work.midstate, work.data + 64,
				        work.hash, work.target,
					max_nonce, &hashes_done);
			break;

#ifdef WANT_CRYPTOPP_ASM32
		case ALGO_CRYPTOPP_ASM32:
			rc = scanhash_asm32(thr_id, work.midstate, work.data + 64,
				        work.hash, work.target,
					max_nonce, &hashes_done);
			break;
#endif

		default:
			/* should never happen */
			goto out;
		}

		/* record scanhash elapsed time */
		gettimeofday(&tv_end, NULL);
		timeval_subtract(&diff, &tv_end, &tv_start);

		hashmeter(thr_id, &diff, hashes_done);

		/* adjust max_nonce to meet target scan time */
		if (diff.tv_usec > 500000)
			diff.tv_sec++;
		if (diff.tv_sec > 0) {
			max64 =
			   ((uint64_t)hashes_done * opt_scantime) / diff.tv_sec;
			if (max64 > 0xfffffffaULL)
				max64 = 0xfffffffaULL;
			max_nonce = max64;
		}

		/* if nonce found, submit work */
		if (rc && !submit_work(mythr, &work))
			break;
	}

out:
	tq_freeze(mythr->q);

	return NULL;
}
#else

static void *miner_thread(void *userdata)
{
    struct thr_info *mythr = userdata;
    int thr_id = mythr->id;
    struct work work = {{0}};
    uint32_t max_nonce;
    uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1) - 0x20;
    unsigned char *scratchbuf = NULL;
    char s[16];
    int i;
    
    /* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
     * and if that fails, then SCHED_BATCH. No need for this to be an
     * error if it fails */
    if (!opt_benchmark) {
        setpriority(PRIO_PROCESS, 0, 19);
        drop_policy();
    }
    
    /* Cpu affinity only makes sense if the number of threads is a multiple
     * of the number of CPUs */
    if (num_processors > 1 && opt_n_threads % num_processors == 0) {
        if (!opt_quiet)
            applog(LOG_INFO, "Binding thread %d to cpu %d",
                   thr_id, thr_id % num_processors);
        affine_to_cpu(thr_id, thr_id % num_processors);
    }
    
    if (opt_algo == ALGO_SCRYPT) {
        scratchbuf = scrypt_buffer_alloc(opt_scrypt_n);
        if (!scratchbuf) {
            applog(LOG_ERR, "scrypt buffer allocation failed");
            pthread_mutex_lock(&applog_lock);
            exit(1);
        }
    }
    
    while (1) {
        unsigned long hashes_done;
        struct timeval tv_start, tv_end, diff;
        int64_t max64;
        int rc;
        
        {
            int min_scantime = have_longpoll ? LP_SCANTIME : opt_scantime;
            /* obtain new work from internal workio thread */
            pthread_mutex_lock(&g_work_lock);
            if (!have_stratum &&
                (time(NULL) - g_work_time >= min_scantime ||
                 work.data[19] >= end_nonce)) {
                    work_free(&g_work);
                    if (unlikely(!get_work(mythr, &g_work))) {
                        applog(LOG_ERR, "work retrieval failed, exiting "
                               "mining thread %d", mythr->id);
                        pthread_mutex_unlock(&g_work_lock);
                        goto out;
                    }
                    g_work_time = have_stratum ? 0 : time(NULL);
                }
            if (have_stratum) {
                pthread_mutex_unlock(&g_work_lock);
                continue;
            }
        }
        if (memcmp(work.data, g_work.data, 76)) {
            work_free(&work);
            work_copy(&work, &g_work);
            work.data[19] = 0xffffffffU / opt_n_threads * thr_id;
        } else
            work.data[19]++;
        pthread_mutex_unlock(&g_work_lock);
#if 1
        work_restart[thr_id].restart = 0;
#else
        work_restart[thr_id].restart = 1;
#endif
        /* adjust max_nonce to meet target scan time */
        if (have_stratum)
            max64 = LP_SCANTIME;
        else
            max64 = g_work_time + (have_longpoll ? LP_SCANTIME : opt_scantime)
            - time(NULL);
        max64 *= thr_hashrates[thr_id];
        if (max64 <= 0) {
            switch (opt_algo) {
                case ALGO_SCRYPT:
                    max64 = opt_scrypt_n < 16 ? 0x3ffff : 0x3fffff / opt_scrypt_n;
                    break;
                case ALGO_SHA256D:
                    max64 = 0x1fffff;
                    break;
            }
        }
        if (work.data[19] + max64 > end_nonce)
            max_nonce = end_nonce;
        else
            max_nonce = work.data[19] + max64;
        
        hashes_done = 0;
        gettimeofday(&tv_start, NULL);
        
        /* scan nonces for a proof-of-work hash */
        switch (opt_algo) {
            case ALGO_SCRYPT:
                rc = scanhash_scrypt(thr_id, work.data, scratchbuf, work.target,
                                     max_nonce, &hashes_done, opt_scrypt_n);
                break;
                
            case ALGO_SHA256D:
                rc = scanhash_sha256d(thr_id, work.data, work.target,
                                      max_nonce, &hashes_done);
                break;
                
            default:
                /* should never happen */
                goto out;
        }
        
        /* record scanhash elapsed time */
        gettimeofday(&tv_end, NULL);
        timeval_subtract(&diff, &tv_end, &tv_start);
        if (diff.tv_usec || diff.tv_sec) {
            pthread_mutex_lock(&stats_lock);
            thr_hashrates[thr_id] =
            hashes_done / (diff.tv_sec + 1e-6 * diff.tv_usec);
            pthread_mutex_unlock(&stats_lock);
        }
        if (!opt_quiet) {
            sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.2f",
                    1e-3 * thr_hashrates[thr_id]);
            applog(LOG_INFO, "thread %d: %lu hashes, %s khash/s",
                   thr_id, hashes_done, s);
        }
        if (opt_benchmark && thr_id == opt_n_threads - 1) {
            double hashrate = 0.;
            for (i = 0; i < opt_n_threads && thr_hashrates[i]; i++)
                hashrate += thr_hashrates[i];
            if (i == opt_n_threads) {
                sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", 1e-3 * hashrate);
                applog(LOG_INFO, "Total: %s khash/s", s);
            }
        }
        
        /* if nonce found, submit work */
        if (rc && !opt_benchmark && !submit_work(mythr, &work))
            break;
        else
        {
            char data_str[2 * sizeof(work.data) + 1];
            bin2hex(data_str, (unsigned char *)work.data, 80);
            applog(LOG_INFO,"Hash: %s", data_str);
        }
    }
    
out:
    tq_freeze(mythr->q);
    
    return NULL;
}

#endif
static void restart_threads(void)
{
	int i;

	for (i = 0; i < opt_n_threads; i++)
		work_restart[i].restart = 1;
}

static void *longpoll_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	CURL *curl = NULL;
	char *copy_start, *hdr_path, *lp_url = NULL;
	bool need_slash = false;
	int failures = 0;

	hdr_path = tq_pop(mythr->q, NULL);
	if (!hdr_path)
		goto out;

	/* full URL */
	if (strstr(hdr_path, "://")) {
		lp_url = hdr_path;
		hdr_path = NULL;
	}
	
	/* absolute path, on current server */
	else {
		copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
		if (rpc_url[strlen(rpc_url) - 1] != '/')
			need_slash = true;

		lp_url = malloc(strlen(rpc_url) + strlen(copy_start) + 2);
		if (!lp_url)
			goto out;

		sprintf(lp_url, "%s%s%s", rpc_url, need_slash ? "/" : "", copy_start);
	}

	applog(LOG_INFO, "Long-polling activated for %s", lp_url);

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		goto out;
	}

	while (1) {
		json_t *val;

		val = json_rpc_call(curl, lp_url, rpc_userpass, rpc_req,
				    false, true);
		if (likely(val)) {
			failures = 0;
			
// 기존에 받아 온 내용과 새로 받아온 내용이 다른 것을 비교해야함.
#if 1
//           applog(DEBUG,"longpool Thread =%s",json_dumps(val, JSON_INDENT(0)));
            json_t *tmp =json_object_get(val,"result");
           tmp = json_object_get(tmp, "mintime");
            if (!tmp || !json_is_real(tmp)) {
                applog(LOG_ERR, "JSON invalid curtime");
                tmp = json_object_get(tmp, "height");
                if(!tmp || !json_is_real(tmp)){
                    applog(LOG_ERR, "JSON invalid height");
                }
            }
            else{
                uint32_t nCurTime = (int)json_real_value(tmp);
                if(_blockCurTime == nCurTime)
                    continue;
                
                applog(LOG_INFO, "LONGPOLL detected new block nCurTime= %u", nCurTime);
            }
            
#endif
            json_decref(val);
			restart_threads();
		} else {
			if (failures++ < 10) {
				sleep(30);
				applog(LOG_ERR,
					"longpoll failed, sleeping for 30s");
			} else {
				applog(LOG_ERR,
					"longpoll failed, ending thread");
				goto out;
			}
		}
	}

out:
	free(hdr_path);
	free(lp_url);
	tq_freeze(mythr->q);
	if (curl)
		curl_easy_cleanup(curl);

	return NULL;
}

static void show_usage(void)
{
	int i;

	printf("minerd version %s\n\n", VERSION);
	printf("Usage:\tminerd [options]\n\nSupported options:\n");
	for (i = 0; i < ARRAY_SIZE(options_help); i++) {
		struct option_help *h;

		h = &options_help[i];
		printf("--%s\n%s\n\n", h->name, h->helptext);
	}

	exit(1);
}

static void show_usage_and_exit(int status)
{
    if (status)
        fprintf(stderr, "Try `" PROGRAM_NAME " --help' for more information.\n");
    
    exit(status);
}

static void parse_arg (int key, char *arg)
{
	int v, i;

	switch(key) {
	case 'a':
		for (i = 0; i < ARRAY_SIZE(algo_names); i++) {
			if (algo_names[i] &&
			    !strcmp(arg, algo_names[i])) {
				opt_algo = i;
				break;
			}
		}
		if (i == ARRAY_SIZE(algo_names))
			show_usage();
		break;
	case 'c': {
		json_error_t err;
		if (opt_config)
			json_decref(opt_config);
#if JANSSON_MAJOR_VERSION >= 2
		opt_config = json_load_file(arg, 0, &err);
#else
		opt_config = json_load_file(arg, &err);
#endif
		if (!json_is_object(opt_config)) {
			applog(LOG_ERR, "JSON decode of '%s' failed(%d): %s", arg, err.line, err.text);
			show_usage();
		}
		break;
	}
	case 'q':
		opt_quiet = true;
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'p':
		free(rpc_pass);
		rpc_pass = strdup(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999)	/* sanity check */
			show_usage();

		opt_retries = v;
		break;
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage();

		opt_fail_pause = v;
		break;
	case 's':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage();

		opt_scantime = v;
		break;
	case 't':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage();

		opt_n_threads = v;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 1001:			/* --url */
		if (strncmp(arg, "http://", 7) &&
		    strncmp(arg, "https://", 8))
			show_usage();

		free(rpc_url);
		rpc_url = strdup(arg);
		break;
	case 1002:			/* --userpass */
		if (!strchr(arg, ':'))
			show_usage();

		free(rpc_userpass);
		rpc_userpass = strdup(arg);
		break;
	case 1003:
		want_longpoll = false;
		break;
	case 1004:
		use_syslog = true;
		break;
    case 'd':
        {
            pk_script_size = address_to_script(pk_script, sizeof(pk_script), arg);
            if (!pk_script_size) {
                fprintf(stderr, " invalid address -- '%s'\n", arg);
                show_usage_and_exit(1);
            }
            break;
        }
	default:
		show_usage();
	}

#ifdef WIN32
	if (!opt_n_threads)
		opt_n_threads = 1;
#else
	num_processors = sysconf(_SC_NPROCESSORS_ONLN);
	if (!opt_n_threads)
		opt_n_threads = num_processors;
#endif /* !WIN32 */
}

static void parse_config(void)
{
	int i;
	json_t *val;

	if (!json_is_object(opt_config))
		return;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		if (!options[i].name)
			break;
		if (!strcmp(options[i].name, "config"))
			continue;

		val = json_object_get(opt_config, options[i].name);
		if (!val)
			continue;

		if (options[i].has_arg && json_is_string(val)) {
			char *s = strdup(json_string_value(val));
			if (!s)
				break;
			parse_arg(options[i].val, s);
			free(s);
		} else if (!options[i].has_arg && json_is_true(val))
			parse_arg(options[i].val, "");
		else
			applog(LOG_ERR, "JSON option %s invalid",
				options[i].name);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
	int key;

	while (1) {
        key = getopt_long(argc, argv, "a:c:d:qDPr:s:t:h?", options, NULL);
		if (key < 0)
			break;

		parse_arg(key, optarg);
	}

	parse_config();
}

int main (int argc, char *argv[])
{
	struct thr_info *thr;
	int i;

	rpc_url = strdup(DEF_RPC_URL);

	/* parse command line */
	parse_cmdline(argc, argv);

	if (!rpc_userpass) {
		if (!rpc_user || !rpc_pass) {
			applog(LOG_ERR, "No login credentials supplied");
			return 1;
		}
		rpc_userpass = malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		if (!rpc_userpass)
			return 1;
		sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
	}

    thr_hashrates = (double *) calloc(opt_n_threads, sizeof(double));
    if (!thr_hashrates)
        return 1;
    
	pthread_mutex_init(&time_lock, NULL);

#ifdef HAVE_SYSLOG_H
	if (use_syslog)
		openlog("cpuminer", LOG_PID, LOG_USER);
#endif

	work_restart = calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return 1;

	thr_info = calloc(opt_n_threads + 2, sizeof(*thr));
	if (!thr_info)
		return 1;

	/* init workio thread info */
	work_thr_id = opt_n_threads;
	thr = &thr_info[work_thr_id];
	thr->id = work_thr_id;
	thr->q = tq_new();
	if (!thr->q)
		return 1;

	/* start work I/O thread */
	if (pthread_create(&thr->pth, NULL, workio_thread, thr)) {
		applog(LOG_ERR, "workio thread create failed");
		return 1;
	}

	/* init longpoll thread info */
	if (want_longpoll) {
		longpoll_thr_id = opt_n_threads + 1;
		thr = &thr_info[longpoll_thr_id];
		thr->id = longpoll_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		/* start longpoll thread */
		if (unlikely(pthread_create(&thr->pth, NULL, longpoll_thread, thr))) {
			applog(LOG_ERR, "longpoll thread create failed");
			return 1;
		}
	} else
		longpoll_thr_id = -1;

	/* start mining threads */
	for (i = 0; i < opt_n_threads; i++) {
		thr = &thr_info[i];

		thr->id = i;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		if (unlikely(pthread_create(&thr->pth, NULL, miner_thread, thr))) {
			applog(LOG_ERR, "thread %d create failed", i);
			return 1;
		}

		sleep(1);	/* don't pound RPC server all at once */
	}

	applog(LOG_INFO, "%d miner threads started, "
		"using SHA256 '%s' algorithm.",
		opt_n_threads,
		algo_names[opt_algo]);

	/* main loop - simply wait for workio thread to exit */
	pthread_join(thr_info[work_thr_id].pth, NULL);

	applog(LOG_INFO, "workio thread dead, exiting.");

	return 0;
}

