/*
 * testbed/legacy/legacy_ecdh_server.c
 * ===================================
 * Genuine OpenSSL 1.0.2g Static ECDH SMTP Server Daemon for PCAP-084.
 *
 * Wire Semantics (RFC 4492 §2.1):
 *   - Cipher: TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xC004)
 *   - Protocol: TLS 1.0 (TLSv1)
 *   - Certificate: Not-yet-valid ECDSA leaf with keyUsage = keyAgreement, digitalSignature
 *   - Handshake Flight: ClientHello -> ServerHello -> Certificate -> ServerHelloDone ->
 *                       ClientKeyExchange -> ChangeCipherSpec -> Finished
 *   - CRITICAL RFC MANDATE: Zero ServerKeyExchange messages transmitted!
 *   - SMTP Exchange: 220 banner, EHLO, 250 OK, QUIT, 221 Bye
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
    const char *cert_file = NULL;
    const char *key_file = NULL;
    int port = 465;
    int single_conn = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_file = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--loop") == 0) {
            single_conn = 0;
        }
    }

    if (!cert_file || !key_file) {
        fprintf(stderr, "Usage: %s --cert <cert.pem> --key <key.pem> [--port <port>]\n", argv[0]);
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLSv1_server_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL_CTX\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load certificate %s\n", cert_file);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load private key %s\n", key_file);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate public key\n");
        return 1;
    }

    // Set static ECDH cipher suite (RFC 4492 0xC004)
    if (SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-SHA") <= 0) {
        fprintf(stderr, "Failed to set cipher list ECDH-ECDSA-AES128-SHA\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind failed");
        return 1;
    }

    if (listen(listen_fd, 5) < 0) {
        perror("listen failed");
        return 1;
    }

    printf("[legacy_ecdh_server] Listening on port %d with cipher ECDH-ECDSA-AES128-SHA\n", port);
    printf("READY\n");
    fflush(stdout);

    do {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int conn_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (conn_fd < 0) {
            perror("accept failed");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("[legacy_ecdh_server] Accepted connection from %s:%d\n", client_ip, ntohs(client_addr.sin_port));
        fflush(stdout);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, conn_fd);

        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "[legacy_ecdh_server] SSL_accept failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(conn_fd);
            continue;
        }

        printf("[legacy_ecdh_server] Handshake complete: cipher=%s version=%s\n",
               SSL_get_cipher_name(ssl), SSL_get_version(ssl));
        fflush(stdout);

        // SMTP Interaction
        SSL_write(ssl, "220 mail.test.local ESMTP Postfix\r\n", 35);

        char buf[512];
        int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = 0;
            if (strstr(buf, "EHLO")) {
                SSL_write(ssl, "250-mail.test.local\r\n250 PIPELINING\r\n250 8BITMIME\r\n250 OK\r\n", 59);
            }
        }

        bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = 0;
            if (strstr(buf, "QUIT")) {
                SSL_write(ssl, "221 2.0.0 Bye\r\n", 15);
            }
        }

        usleep(100000); // 100ms
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(conn_fd);
        printf("[legacy_ecdh_server] Transaction completed successfully\n");
        fflush(stdout);
    } while (!single_conn);

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}
