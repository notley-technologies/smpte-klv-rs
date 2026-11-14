#include <smpte_klv.h>
#include <assert.h>
#include <string.h>

static const uint8_t title[16] = {6, 14, 43, 52, 1, 1, 1, 1, 1, 5, 2};
static const uint8_t text[] = {42, 7};
static const uint8_t local[16] = {6, 14, 43, 52, 2, 3, 1, 1, 15, 1, 1, 1};

static void parse_and_encode(void)
{
    uint8_t packet[256];
    uint8_t value[128] = {7};
    size_t n, needed;
    smpte_klv_triplet t = {0};
    t.struct_size = sizeof t;
    assert(smpte_klv_abi_version() == SMPTE_KLV_ABI_VERSION);
    assert(strcmp(smpte_klv_version(), SMPTE_KLV_VERSION_STRING) == 0);
    assert(strcmp(smpte_klv_status_string(SMPTE_KLV_INCOMPLETE), "more input required") == 0);
    assert(smpte_klv_encode_triplet(title, value, sizeof value, NULL, 0, &n) == SMPTE_KLV_ERR_BUFFER);
    assert(n == 146);
    memset(packet, 0xAA, sizeof packet);
    assert(smpte_klv_encode_triplet(title, value, sizeof value, packet, n - 1, &n) == SMPTE_KLV_ERR_BUFFER);
    assert(packet[0] == 0xAA && packet[n - 2] == 0xAA);
    assert(smpte_klv_encode_triplet(title, value, sizeof value, packet, sizeof packet, &n) == SMPTE_KLV_OK);
    assert(!memcmp(packet, title, 16) && packet[16] == 0x81 && packet[17] == 128);
    assert(smpte_klv_parse(packet, n - 1, 0, &t, &needed) == SMPTE_KLV_INCOMPLETE && needed == n);
    assert(smpte_klv_parse(packet, sizeof packet, 0, &t, &needed) == SMPTE_KLV_OK && needed == 0);
    assert(t.struct_size == sizeof t && t.group == SMPTE_KLV_GROUP_NONE && t.offset == 0);
    assert(t.raw == packet && t.raw_len == n && t.value == packet + 18 && t.value_len == sizeof value);
    assert(!memcmp(t.key, title, 16) && !memcmp(t.value, value, sizeof value));

    packet[16] = 0x80;
    assert(smpte_klv_parse(packet, n, 0, &t, NULL) == SMPTE_KLV_ERR_MALFORMED);
    assert(smpte_klv_parse(packet, n, SMPTE_KLV_INDEFINITE_TO_END, &t, NULL) == SMPTE_KLV_OK);
    assert(t.value_len == n - 17);
    t.struct_size = 3;
    assert(smpte_klv_parse(packet, n, 0, &t, NULL) == SMPTE_KLV_ERR_INVALID);
    t.struct_size = sizeof t;
    assert(smpte_klv_parse(NULL, 0, 0, &t, &needed) == SMPTE_KLV_INCOMPLETE && needed == 17);
    assert(smpte_klv_parse(NULL, 1, 0, &t, NULL) == SMPTE_KLV_ERR_NULL);
    assert(smpte_klv_parse(packet, SIZE_MAX, 0, &t, NULL) == SMPTE_KLV_ERR_INVALID);
    assert(smpte_klv_parse(packet, n, UINT32_MAX, &t, NULL) == SMPTE_KLV_ERR_INVALID);
    assert(smpte_klv_parse(packet, n, 0, NULL, NULL) == SMPTE_KLV_ERR_NULL);
    assert(smpte_klv_encode_triplet(NULL, value, 1, packet, sizeof packet, &n) == SMPTE_KLV_ERR_NULL);
    assert(smpte_klv_encode_triplet(title, NULL, 0, NULL, 1, &n) == SMPTE_KLV_ERR_NULL);
    assert(smpte_klv_encode_triplet(title, NULL, 0, packet, sizeof packet, &n) == SMPTE_KLV_OK && n == 17);
}

typedef struct {
    uint32_t kind;
    unsigned visits;
} visit_state;

static int32_t check_item(const smpte_klv_item *i, void *context)
{
    visit_state *s = context;
    assert(i->struct_size == sizeof *i && i->group == s->kind);
    assert(i->value_len == sizeof text && !memcmp(i->value, text, sizeof text));
    if (s->kind == SMPTE_KLV_LOCAL_SET)
        assert(i->tag == 7);
    else if (s->kind == SMPTE_KLV_UNIVERSAL_SET || s->kind == SMPTE_KLV_GLOBAL_SET)
        assert(!memcmp(i->key, title, sizeof title));
    else
        assert(i->tag == 0);
    return (int32_t)s->visits++;
}

static void groups(void)
{
    uint8_t key[16] = {6, 14, 43, 52, 2, 1, 8, 1, 6, 14, 43, 52, 1, 1, 1};
    uint8_t packet[64];
    smpte_klv_triplet t = {0};
    smpte_klv_encoder *encoder;
    visit_state state;
    size_t n;
    t.struct_size = sizeof t;
    for (key[5] = 1; key[5] <= 5; ++key[5]) {
        const uint8_t *item_key = key[5] <= 2 ? title : NULL;
        assert(smpte_klv_encoder_new(key, &encoder) == SMPTE_KLV_OK);
        if (key[5] <= 2)
            assert(smpte_klv_encoder_add(encoder, NULL, 0, NULL, 0) == SMPTE_KLV_ERR_NULL);
        if (key[5] == 3)
            assert(smpte_klv_encoder_add(encoder, NULL, 256, text, sizeof text) == SMPTE_KLV_ERR_INVALID);
        assert(smpte_klv_encoder_add(encoder, item_key, key[5] == 3 ? 7 : 0, text, sizeof text) == SMPTE_KLV_OK);
        assert(smpte_klv_encoder_write(encoder, NULL, 0, &n) == SMPTE_KLV_ERR_BUFFER && n <= sizeof packet);
        assert(smpte_klv_encoder_write(encoder, packet, n, &n) == SMPTE_KLV_OK);
        smpte_klv_encoder_free(encoder);
        assert(smpte_klv_parse(packet, n, 0, &t, NULL) == SMPTE_KLV_OK && t.group == key[5]);
        state.kind = t.group;
        state.visits = 0;
        assert(smpte_klv_visit_group(t.key, t.value, t.value_len, 0, check_item, &state) == SMPTE_KLV_OK);
        assert(state.visits == 1);
        assert(smpte_klv_visit_group(t.key, t.value, t.value_len, 0, check_item, &state) == SMPTE_KLV_STOPPED);
    }
    assert(smpte_klv_encoder_new(title, &encoder) == SMPTE_KLV_ERR_INVALID && encoder == NULL);
    assert(smpte_klv_visit_group(local, text, 1, 0, check_item, &state) == SMPTE_KLV_ERR_MALFORMED);
    assert(smpte_klv_visit_group(title, NULL, 0, 0, check_item, &state) == SMPTE_KLV_ERR_INVALID);
    assert(smpte_klv_visit_group(local, NULL, 0, 0, NULL, NULL) == SMPTE_KLV_ERR_NULL);
    smpte_klv_encoder_free(NULL);
}

static void stream(void)
{
    smpte_klv_decoder *d;
    smpte_klv_config c = {0};
    smpte_klv_triplet frame = {0};
    smpte_klv_stats stats = {0};
    uint8_t packet[32];
    uint8_t truncated[] = {6, 14, 43, 52, 1};
    size_t n, i;
    struct { smpte_klv_config c; uint64_t guard; } future = {{0}, 42};
    future.c.struct_size = sizeof future;
    assert(smpte_klv_config_default(&future.c) == SMPTE_KLV_OK && future.guard == 42);
    assert(future.c.struct_size == sizeof c && future.c.max_queue_bytes == (64u << 20));

    c.struct_size = offsetof(smpte_klv_config, max_value_len);
    c.max_value_len = 42;
    assert(smpte_klv_config_default(&c) == SMPTE_KLV_OK && c.max_value_len == 42);
    c.flags = SMPTE_KLV_INDEFINITE_TO_END;
    assert(smpte_klv_decoder_new(&c, &d) == SMPTE_KLV_ERR_INVALID && d == NULL);
    c.flags = 0;
    assert(smpte_klv_decoder_new(&c, &d) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_filter(d, title) == SMPTE_KLV_OK);
    assert(smpte_klv_encode_triplet(local, NULL, 0, packet, sizeof packet, &n) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_push(d, packet, n) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_push(d, NULL, 1) == SMPTE_KLV_ERR_NULL);
    assert(smpte_klv_decoder_push(d, NULL, 0) == SMPTE_KLV_OK);
    assert(smpte_klv_encode_triplet(title, text, sizeof text, packet, sizeof packet, &n) == SMPTE_KLV_OK);
    for (i = 0; i < n; ++i)
        assert(smpte_klv_decoder_push(d, packet + i, 1) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_next(d, &frame) == SMPTE_KLV_ERR_INVALID);
    frame.struct_size = sizeof frame;
    assert(smpte_klv_decoder_next(d, &frame) == SMPTE_KLV_OK);
    assert(frame.offset == 17 && frame.raw_len == n && !memcmp(frame.raw, packet, n));
    assert(smpte_klv_decoder_filter(d, NULL) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_push(d, truncated, sizeof truncated) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_finish(d) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_next(d, &frame) == SMPTE_KLV_EMPTY);
    assert(frame.value_len == sizeof text && !memcmp(frame.value, text, sizeof text));
    stats.struct_size = sizeof stats;
    assert(smpte_klv_decoder_stats(d, &stats) == SMPTE_KLV_OK);
    assert(stats.bytes == 17 + n + sizeof truncated && stats.frames == 1 && stats.frame_bytes == n);
    assert(stats.filtered == 1 && stats.truncated_at_finish == 1 && stats.bytes_skipped == 17 + sizeof truncated);
    assert(stats.queued == 0 && stats.buffered == 0);
    smpte_klv_decoder_free(d);
    smpte_klv_decoder_free(NULL);
}

int main(void)
{
    parse_and_encode();
    groups();
    stream();
    return 0;
}
