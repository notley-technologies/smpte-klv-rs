/* SMPTE ST 336 KLV, public C ABI.
 *
 * Compare smpte_klv_abi_version() with SMPTE_KLV_ABI_VERSION before use.
 * Within an ABI version, functions and constants keep their meanings and
 * struct fields may be appended. Set struct_size to sizeof your struct
 * before passing it to the library. Outputs report the number of bytes
 * written. Missing configuration fields use their defaults.
 *
 * Pass valid, aligned pointers. Writable outputs must be separate from
 * each other and from inputs. Byte buffers may be NULL when their length
 * is zero. Use each opaque handle from one thread at a time. After an
 * internal panic, free the affected handle. Free functions accept NULL.
 */
#ifndef SMPTE_KLV_H
#define SMPTE_KLV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SMPTE_KLV_ABI_VERSION 1
#define SMPTE_KLV_VERSION_MAJOR 0
#define SMPTE_KLV_VERSION_MINOR 1
#define SMPTE_KLV_VERSION_PATCH 0
#define SMPTE_KLV_VERSION_STRING "0.1.0"

typedef int32_t smpte_klv_status;
#define SMPTE_KLV_OK 0
#define SMPTE_KLV_EMPTY 1           /* no frame is waiting */
#define SMPTE_KLV_INCOMPLETE 2      /* input ends inside a triplet */
#define SMPTE_KLV_STOPPED 3         /* the group visitor requested a stop */
#define SMPTE_KLV_ERR_NULL (-1)
#define SMPTE_KLV_ERR_INVALID (-2)  /* argument or option */
#define SMPTE_KLV_ERR_MALFORMED (-3)
#define SMPTE_KLV_ERR_BUFFER (-4)   /* output is too small */
#define SMPTE_KLV_ERR_PANIC (-5)
#define SMPTE_KLV_ERR_POISONED (-6)

/* Decode flags. Zero selects the Rust library's strict defaults. */
#define SMPTE_KLV_LENIENT 1u
#define SMPTE_KLV_ALLOW_NON_SMPTE 2u
#define SMPTE_KLV_INDEFINITE_TO_END 4u /* buffer parsing only */
#define SMPTE_KLV_SKIP_FILL 8u        /* streams and set iteration */

#define SMPTE_KLV_GROUP_NONE 0u
#define SMPTE_KLV_UNIVERSAL_SET 1u
#define SMPTE_KLV_GLOBAL_SET 2u
#define SMPTE_KLV_LOCAL_SET 3u
#define SMPTE_KLV_VARIABLE_PACK 4u
#define SMPTE_KLV_DEFINED_PACK 5u

typedef struct smpte_klv_decoder smpte_klv_decoder;
typedef struct smpte_klv_encoder smpte_klv_encoder;

typedef struct smpte_klv_triplet {
    uint32_t struct_size;
    uint32_t group;              /* SMPTE_KLV_GROUP_NONE for opaque values */
    uint64_t offset;             /* stream position, zero for buffer parsing */
    uint8_t key[16];
    const uint8_t *raw;          /* key, length and value as received */
    size_t raw_len;
    const uint8_t *value;
    size_t value_len;
} smpte_klv_triplet;

typedef struct smpte_klv_item {
    uint32_t struct_size;
    uint32_t group;              /* coding of the containing group */
    uint64_t tag;                /* Local Set tag or zero-based pack index */
    uint8_t key[16];             /* item key for Universal and Global Sets */
    const uint8_t *value;
    size_t value_len;
} smpte_klv_item;

typedef struct smpte_klv_config {
    uint32_t struct_size;
    uint32_t flags;              /* stream decode flags */
    uint64_t max_value_len;      /* default 16 MiB */
    uint64_t max_queue_bytes;    /* default 64 MiB */
    uint64_t max_skip_len;       /* default UINT64_MAX */
    uint32_t resync_on_reserved_category; /* 0 or 1 */
    uint32_t reserved;           /* set to zero */
} smpte_klv_config;

typedef struct smpte_klv_stats {
    uint32_t struct_size;
    uint32_t reserved;
    uint64_t bytes;
    uint64_t frames;
    uint64_t frame_bytes;
    uint64_t bytes_skipped;
    uint64_t resyncs;
    uint64_t malformed;
    uint64_t oversized;
    uint64_t fill_skipped;
    uint64_t filtered;
    uint64_t dropped;
    uint64_t truncated_at_finish;
    uint64_t buffered;
    uint64_t queued;
} smpte_klv_stats;

uint32_t smpte_klv_abi_version(void);
const char *smpte_klv_version(void);
const char *smpte_klv_status_string(smpte_klv_status status); /* static string */

/* Parse the first triplet. Advance by out->raw_len to read the next.
 * Its byte pointers borrow data and stay valid while data is unchanged.
 * If supplied, *needed receives the minimum total input size to make
 * progress on INCOMPLETE, and zero on success or malformed input. */
smpte_klv_status smpte_klv_parse(const uint8_t *data, size_t len, uint32_t flags,
                                 smpte_klv_triplet *out, size_t *needed);

/* Visit items using the coding declared by key (16 bytes). A Defined-Length
 * Pack is delivered as one value, which the caller splits using its schema.
 * The item record lives for the callback. Its value points into the original
 * buffer. Return zero to continue or nonzero for SMPTE_KLV_STOPPED.
 * Callbacks must return normally and keep the input alive and unchanged. */
typedef int32_t (*smpte_klv_visitor)(const smpte_klv_item *item, void *context);
smpte_klv_status smpte_klv_visit_group(const uint8_t key[16], const uint8_t *value, size_t len,
                                       uint32_t flags, smpte_klv_visitor visit, void *context);

/* Write a triplet with a minimal BER length. The key is copied verbatim.
 * All encode functions that take a destination set *written to the required
 * size on OK or ERR_BUFFER. Pass NULL and capacity zero for a size query
 * (ERR_BUFFER). A short buffer is left untouched. */
smpte_klv_status smpte_klv_encode_triplet(const uint8_t key[16], const uint8_t *value, size_t len,
                                          uint8_t *dest, size_t capacity, size_t *written);

/* Build a set or pack. The group key selects its tag and length coding.
 * Constructors set *out to NULL on error. */
smpte_klv_status smpte_klv_encoder_new(const uint8_t key[16], smpte_klv_encoder **out);
/* Universal/Global Sets require item_key. Local Sets use tag. Packs append
 * in order. Pass NULL and zero for unused key and tag arguments. */
smpte_klv_status smpte_klv_encoder_add(smpte_klv_encoder *encoder, const uint8_t item_key[16],
                                       uint64_t tag, const uint8_t *value, size_t len);
smpte_klv_status smpte_klv_encoder_write(smpte_klv_encoder *encoder, uint8_t *dest,
                                         size_t capacity, size_t *written);
void smpte_klv_encoder_free(smpte_klv_encoder *encoder);

smpte_klv_status smpte_klv_config_default(smpte_klv_config *config);
/* Pass NULL for the default config. On error *out is set to NULL. */
smpte_klv_status smpte_klv_decoder_new(const smpte_klv_config *config, smpte_klv_decoder **out);
/* Keep only frames with this key. NULL clears the filter. */
smpte_klv_status smpte_klv_decoder_filter(smpte_klv_decoder *decoder, const uint8_t key[16]);
smpte_klv_status smpte_klv_decoder_push(smpte_klv_decoder *decoder, const uint8_t *data, size_t len);
/* At end of input, finish and drain again to collect any recovered frames. */
smpte_klv_status smpte_klv_decoder_finish(smpte_klv_decoder *decoder);
/* A frame's byte pointers are valid until the next successful next call
 * on this decoder or until it is freed. Copy bytes you need for longer. */
smpte_klv_status smpte_klv_decoder_next(smpte_klv_decoder *decoder, smpte_klv_triplet *out);
smpte_klv_status smpte_klv_decoder_stats(smpte_klv_decoder *decoder, smpte_klv_stats *out);
void smpte_klv_decoder_free(smpte_klv_decoder *decoder);

#ifdef __cplusplus
}
#endif
#endif /* SMPTE_KLV_H */
