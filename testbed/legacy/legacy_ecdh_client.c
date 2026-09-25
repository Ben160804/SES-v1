/*
 * testbed/legacy/legacy_ecdh_client.c
 * ===================================
 * Genuine OpenSSL 1.0.2g Static ECDH SMTP Client for PCAP-084.
 *
 * Wire Semantics (RFC 4492 §2.1):
 *   - Offers: TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xC004)
 *   - Protocol: TLS 1.0 (TLSv1)
 *   - Certificate Validation: Permissive / SSL_VERIFY_NONE during generation
 *     so the intentionally not-yet-valid certificate allows the full handshake
 *     and encrypted SMTP transaction to be captured on the wire (Condition 2).
 *   - Sends ClientKeyExchange containing client ephemeral ECDH point.
 *   - Completes Finished and exchanges encrypted SMTP commands (EHLO, QUIT).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main(int argc, char **argv) {
    const char *host = "172.28.0.40";
    int port = 465;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        }
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create client SSL_CTX\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Permissive certificate verification during generation mode (Condition 2)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Offer static ECDH cipher suite (0xC004)
    if (SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-SHA") <= 0) {
        fprintf(stderr, "Failed to set cipher list ECDH-ECDSA-AES128-SHA\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect failed");
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, "mail.test.local");

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[legacy_ecdh_client] SSL_connect failed!\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("[legacy_ecdh_client] Connected! Negotiated cipher=%s version=%s\n",
           SSL_get_cipher_name(ssl), SSL_get_version(ssl));
    fflush(stdout);

    // Read SMTP banner
    char buf[512];
    int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        fprintf(stderr, "[legacy_ecdh_client] Failed to read SMTP banner\n");
        return 1;
    }
    buf[bytes] = 0;
    printf("[legacy_ecdh_client] S: %s", buf);
    fflush(stdout);

    // Send EHLO
    SSL_write(ssl, "EHLO client.test.local\r\n", 24);
    bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        fprintf(stderr, "[legacy_ecdh_client] Failed to read EHLO response\n");
        return 1;
    }
    buf[bytes] = 0;
    printf("[legacy_ecdh_client] S: %s", buf);
    fflush(stdout);

    // Send QUIT
    SSL_write(ssl, "QUIT\r\n", 6);
    bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes > 0) {
        buf[bytes] = 0;
        printf("[legacy_ecdh_client] S: %s", buf);
    }
    fflush(stdout);

    usleep(50000);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    printf("[legacy_ecdh_client] Transaction completed cleanly\n");
    return 0;
}
