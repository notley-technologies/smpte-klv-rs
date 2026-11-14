/* Compare the borrowed and streaming C APIs on arbitrary value bytes. */
#include <smpte_klv.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static int32_t item(const smpte_klv_item *view, void *context)
{
    size_t *remaining = context;
    assert(view->struct_size == sizeof *view && view->value_len <= *remaining);
    *remaining -= view->value_len;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
    uint8_t key[16] = {6, 14, 43, 52, 2, 3, 8, 1, 6, 14, 43, 52, 1, 1, 1};
    smpte_klv_decoder *decoder;
    smpte_klv_triplet t = {0};
    smpte_klv_status status;
    size_t n, split, needed, remaining = len;
    uint8_t *packet;
    if (len == 0 || len > (1u << 20)) return 0;
    key[5] = data[0];
    t.struct_size = sizeof t;
    status = smpte_klv_parse(data, len, 0, &t, &needed);
    if (status == SMPTE_KLV_INCOMPLETE)
        assert(needed > len);
    else if (status == SMPTE_KLV_OK)
        assert(!needed && t.raw == data && t.raw_len <= len && t.value_len < t.raw_len);
    else
        assert(status == SMPTE_KLV_ERR_MALFORMED && !needed);

    status = smpte_klv_visit_group(key, data, len, 0, item, &remaining);
    assert(status == SMPTE_KLV_OK || status == SMPTE_KLV_ERR_MALFORMED || status == SMPTE_KLV_ERR_INVALID);
    assert(smpte_klv_encode_triplet(key, data, len, NULL, 0, &n) == SMPTE_KLV_ERR_BUFFER);
    assert(n > len && n <= len + 25);
    packet = malloc(n);
    assert(packet);
    assert(smpte_klv_encode_triplet(key, data, len, packet, n, &n) == SMPTE_KLV_OK);

    split = data[len - 1] % n;
    assert(smpte_klv_decoder_new(NULL, &decoder) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_push(decoder, packet, split) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_next(decoder, &t) == SMPTE_KLV_EMPTY);
    assert(smpte_klv_decoder_push(decoder, packet + split, n - split) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_finish(decoder) == SMPTE_KLV_OK);
    assert(smpte_klv_decoder_next(decoder, &t) == SMPTE_KLV_OK);
    assert(t.raw_len == n && !memcmp(t.raw, packet, n));
    assert(t.value_len == len && !memcmp(t.value, data, len));
    smpte_klv_decoder_free(decoder);
    free(packet);
    return 0;
}
