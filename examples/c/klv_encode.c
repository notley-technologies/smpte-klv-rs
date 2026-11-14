/* Write a Local Set with a BER-OID tag and a one-byte value. */
#include <smpte_klv.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    const uint8_t key[16] = {6, 14, 43, 52, 2, 11, 1, 1, 14, 1, 3, 1, 1, 0, 0, 0};
    const uint8_t value = 42;
    uint8_t packet[64];
    size_t written;
    smpte_klv_encoder *encoder;
    smpte_klv_status status;
    FILE *file;

    if (argc != 2) {
        fprintf(stderr, "usage: klv_encode <output.klv>\n");
        return 2;
    }
    status = smpte_klv_encoder_new(key, &encoder);
    if (status == SMPTE_KLV_OK)
        status = smpte_klv_encoder_add(encoder, NULL, 129, &value, sizeof value);
    if (status == SMPTE_KLV_OK)
        status = smpte_klv_encoder_write(encoder, packet, sizeof packet, &written);
    smpte_klv_encoder_free(encoder);
    if (status != SMPTE_KLV_OK) {
        fprintf(stderr, "%s\n", smpte_klv_status_string(status));
        return 1;
    }

    file = fopen(argv[1], "wb");
    if (!file) {
        perror(argv[1]);
        return 1;
    }
    if (fwrite(packet, 1, written, file) != written) {
        perror(argv[1]);
        fclose(file);
        return 1;
    }
    if (fclose(file) != 0) {
        perror(argv[1]);
        return 1;
    }
    return 0;
}
