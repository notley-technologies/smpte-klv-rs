/* Print the key, stream offset, and value length of each triplet in a file. */
#include <smpte_klv.h>
#include <inttypes.h>
#include <stdio.h>

static smpte_klv_status drain(smpte_klv_decoder *decoder)
{
    smpte_klv_triplet frame = {0};
    smpte_klv_status status;
    frame.struct_size = sizeof frame;
    while ((status = smpte_klv_decoder_next(decoder, &frame)) == SMPTE_KLV_OK) {
        size_t i;
        printf("@%" PRIu64 " ", frame.offset);
        for (i = 0; i < sizeof frame.key; ++i)
            printf("%02X", (unsigned)frame.key[i]);
        printf(" %zu bytes\n", frame.value_len);
    }
    return status == SMPTE_KLV_EMPTY ? SMPTE_KLV_OK : status;
}

int main(int argc, char **argv)
{
    uint8_t buf[8192];
    smpte_klv_decoder *decoder;
    smpte_klv_status status;
    size_t n;
    FILE *file;
    if (argc != 2) {
        fprintf(stderr, "usage: klv_dump <input.klv>\n");
        return 2;
    }
    file = fopen(argv[1], "rb");
    if (!file) {
        perror(argv[1]);
        return 1;
    }
    status = smpte_klv_decoder_new(NULL, &decoder);
    while (status == SMPTE_KLV_OK && (n = fread(buf, 1, sizeof buf, file)) != 0) {
        status = smpte_klv_decoder_push(decoder, buf, n);
        if (status == SMPTE_KLV_OK)
            status = drain(decoder);
    }
    if (ferror(file)) {
        perror(argv[1]);
        fclose(file);
        smpte_klv_decoder_free(decoder);
        return 1;
    }
    fclose(file);
    if (status == SMPTE_KLV_OK)
        status = smpte_klv_decoder_finish(decoder);
    if (status == SMPTE_KLV_OK)
        status = drain(decoder);
    smpte_klv_decoder_free(decoder);
    if (status != SMPTE_KLV_OK) {
        fprintf(stderr, "%s\n", smpte_klv_status_string(status));
        return 1;
    }
    return 0;
}
