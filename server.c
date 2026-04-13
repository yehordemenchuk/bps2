// 20251106 MD, vylepseny vypis pouzitej metody na vymenu kluca

// 20251103 JP, korektne ukoncenie pri nekompatibilnej vymene kluca

// 20251020 MD, zrusene pouzitie OQS_PROVIDER, pre zakladnu vyucbu  
//              a openssl 3.5 a novsie, nema vyznam ...


/**
 * SSL/TLS Server (Version 1.3, 2018-2025)
 * Cross-platform TLS 1.3 server with OpenSSL 3.5.0, optional OQS provider.
 *
 * WHAT THIS PROGRAM DOES:
 * - Creates a TCP server socket and listens on a given port
 * - Accepts incoming TCP connections
 * - Upgrades them to TLS 1.3 using OpenSSL
 * - Handles each client in a separate thread
 * - Exchanges simple text messages with the client
 *
 * EDUCATIONAL PURPOSE:
 * - Demonstrates the TLS 1.3 handshake
 * - Shows cipher and key exchange group negotiation
 * - Demonstrates multithreaded client handling
 * - Contains artificial delays so students can observe concurrency
 *
 * Contributors (alphabetical): JS, NK, MD, MJ
 *
 * Compile on Linux:
 *   gcc server.c -Wall -Wextra -lssl -lcrypto -pthread -o server
 *
 * Compile on Windows:
 *   gcc server.c -Wall -Wextra -I C:\OPENSSL\include -L C:\OPENSSL\lib \
 *   -lssl -lcrypto -lws2_32 -o server
 *
 * Usage:
 *   ./server <port> <key.pem> <cert.pem>
 *
 * Cert example:
 *   openssl req -x509 -nodes -newkey rsa:2048 \
 *   -keyout server.pem -out server.pem
 */

#ifdef __unix__
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <pthread.h>
#define SOCKLEN_T socklen_t
#define CLOSESOCKET close
#define THREAD_TYPE pthread_t
#define THREAD_CREATE(t, a, f, x) (pthread_create(&t, NULL, f, x) == 0)
#define THREAD_RETURN void*
#define THREAD_RETURN_VALUE NULL
#elif defined _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> 
#define SOCKLEN_T int
#define CLOSESOCKET closesocket
#define THREAD_TYPE HANDLE
#define THREAD_CREATE(t, a, f, x) ((t = CreateThread(NULL, 0, f, x, 0, NULL)) != NULL)
#define THREAD_RETURN DWORD WINAPI
#define THREAD_RETURN_VALUE 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>

#ifdef _WIN32
WSADATA wsa;
#endif

/* ------------------------------------------------------------------
 * CONFIGURATION CONSTANTS
 * ------------------------------------------------------------------*/

/* Supported TLS 1.3 groups (KEX/KEM).
 * For BPS, we use "ffdhe2048".
 * for BIKS, we can use stadard ECDH "X25519"
 * PQC (Hybrid ML-KEM), we can use "X25519MLKEM768"
*/
#define GROUPS "X25519"

#define PORT 443              /* Default port if none is given */
#define BUF_SIZE 1024         /* Buffer size for reading messages */
#define MAX_MSG 5             /* Max number of messages per client */

/* Server waits this many seconds before replying to a client.
 * Purpose: simulate network latency and clearly demonstrate that
 * multiple clients are handled in parallel threads. */
#define DELAY 3

/* Maximum number of pending client connections waiting to be accepted.
 * This controls the size of the OS queue before accept() is called. */
#define BACKLOG 10

/* OpenSSL return codes */
#define OK 1      /* Operation succeeded */
#define FAIL -1   /* Failure */
/* ------------------------------------------------------------------
 * DATA STRUCTURES
 * ------------------------------------------------------------------*/

/* Data passed to each client-handling thread */
typedef struct {
  SSL *ssl;
  int sock;
  struct sockaddr_in addr;
} ClientData;

/* ------------------------------------------------------------------
 * HELPER FUNCTIONS
 * ------------------------------------------------------------------*/

/* Print usage instructions */
void usage(char *bin) {
  printf("Usage: %s <port> <key.pem> <cert.pem>\n", bin);
}

/* Create, bind, and listen on server socket */
int make_sock(int port) {
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 0), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return FAIL;
    }
#endif
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == FAIL) {
        perror("Socket creation failed");
        return FAIL;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
        perror("Bind failed");
        CLOSESOCKET(sock);
        return FAIL;
    }

    if (listen(sock, BACKLOG)) {
        /* Switch socket into listening mode.
         * BACKLOG defines how many pending connection
         * requests can wait before accept() is called.
         * If the queue is full, new clients may get
         * ECONNREFUSED or be silently dropped. */
        perror("Listen failed");
        CLOSESOCKET(sock);
        return FAIL;
    }

    printf("\n[+] Listening on port %d...\n", port);
    return sock;
}

/* info about used Group or Key Encapsulation Method */
void print_tls_info(SSL *ssl)
{
    printf("[+] Protocol: %s\n", SSL_get_version(ssl));

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    printf("Cipher used: %s\n", SSL_CIPHER_get_name(cipher));

    const char *group = SSL_get0_group_name(ssl);
    if (!group) {
        // fallback: try description if group name unavailable
        char desc[256];
        if (SSL_CIPHER_description(cipher, desc, sizeof(desc))) {
            const char *p = strstr(desc, "MLKEM");
            if (p)
                group = p;
        }
    }

    if (group)
        printf("Used group/KEM: %s\n", group);
    else
        printf("Used group/KEM: Unknown\n");
}

/* Init TLS 1.3 SSL context */
SSL_CTX* init_ctx() {
    const SSL_METHOD *m = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(m);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Restrict to TLS 1.3 only */
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != OK ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != OK) {
        fprintf(stderr, "TLS 1.3 setup failed\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

/* Load server certificate and private key */
void load_certs(SSL_CTX *ctx, const char *pem, const char *key) {
    if (SSL_CTX_use_certificate_file(ctx, pem, SSL_FILETYPE_PEM) != OK ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != OK) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("[*] Cert and key loaded\n");

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[-] Key does not match cert\n");
        exit(EXIT_FAILURE);
    }
    printf("[+] Key matches cert\n");

    /* Show signature algorithm of the server certificate */
    X509 *cert = SSL_CTX_get0_certificate(ctx);
    int nid = X509_get_signature_nid(cert);
    printf("Cert signature: %s\n",
           nid == NID_undef ? "Unknown" : OBJ_nid2sn(nid));

#ifdef AUTHENTICATION
    /* Enable client certificate verification if needed */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (SSL_CTX_load_verify_locations(ctx, "myCA.pem", NULL) != OK) {
        fprintf(stderr, "[-] CA cert load failed\n");
        exit(EXIT_FAILURE);
    }
    printf("[*] CA cert loaded\n");
#endif
}

/* Show client certificate details (if provided) */
void show_certs(SSL *ssl) {
    STACK_OF(X509) *chain = SSL_get0_verified_chain(ssl);
    if (chain && sk_X509_num(chain) > 0) {
        X509 *cert = sk_X509_value(chain, 0);
        char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        char *iss  = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        printf("[+] Client certs:\n");
        printf("\tSubject: %s\n", subj ? subj : "Unknown");
        printf("\tIssuer: %s\n", iss ? iss : "Unknown");
        OPENSSL_free(subj);
        OPENSSL_free(iss);
    } else {
        printf("[-] No client certs\n");
    }
}

#ifdef CHECK_SAN
int verify_cert_san_ipv4(X509 *cert, const char *expected_ip) {
    if (!cert || !expected_ip)
        return 0;

    STACK_OF(GENERAL_NAME) *san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!san_names) {
        printf("[-] Certificate has no SAN extension\n");
        return 0;
    }

    int san_count = sk_GENERAL_NAME_num(san_names);
    int match = 0;

    for (int i = 0; i < san_count; i++) {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(san_names, i);

        if (name->type == GEN_IPADD && name->d.iPAddress->length == 4) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, name->d.iPAddress->data, ip_str, sizeof(ip_str));
            printf("[*] Found SAN IPv4: %s\n", ip_str);

            if (strcmp(ip_str, expected_ip) == 0) {
                match = 1;
                break;
            }
        }
    }

    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    if (match) {
        printf("[+] SAN IPv4 verified successfully (%s)\n", expected_ip);
    } else {
        printf("[-] SAN IPv4 does not match expected (%s)\n", expected_ip);
    }

    return match;
}
#endif



/* ------------------------------------------------------------------
 * CLIENT HANDLING
 * ------------------------------------------------------------------*/

/* Conversation with one client */
void routine(ClientData data) {
    SSL *ssl = data.ssl;
    int sock = data.sock;
    struct sockaddr_in addr = data.addr;

    printf("[+] Conn from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    /* Perform TLS 1.3 handshake with the client.
     * This upgrades plain TCP into secure TLS channel. */
    if (SSL_accept(ssl) != OK) {
		int err = SSL_get_error(ssl, -1);
		fprintf(stderr, "[-] TLS handshake failed with client (%d)\n", err);
		ERR_print_errors_fp(stderr);

		SSL_shutdown(ssl);
		SSL_free(ssl);
		CLOSESOCKET(sock);

		printf("[*] Connection closed due to handshake failure. Server still running.\n");
    return;
}


    print_tls_info(ssl);
	
	#ifdef CHECK_SAN
    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
        printf("[*] Connected client IP: %s\n", ip_str);

        if (!verify_cert_san_ipv4(client_cert, ip_str)) {
            printf("[-] SAN verification failed for client IP %s\n", ip_str);
            X509_free(client_cert);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            CLOSESOCKET(sock);
            printf("[*] Client connection closed (SAN mismatch)\n");
            return;
        }
        X509_free(client_cert);
    } else {
        printf("[-] Client certificate not available for SAN check\n");
    }
#endif


    /* Show peer signature algorithm */
    int nid;
    if (SSL_get_peer_signature_nid(ssl, &nid) == OK) {
        printf("[+] Peer signature: %s\n", OBJ_nid2sn(nid));
    } else {
        printf("[+] Peer signature: Unknown\n");
    }

    show_certs(ssl);

    char buf[BUF_SIZE], reply[BUF_SIZE];
    int msg_count = 0;

    /* Read client messages in loop */
    while (msg_count < MAX_MSG) {
		// ADVANCED: Check SSL_get_error(); consider 
		// loop/retry for non-blocking IO; handle SSL_ERROR_ZERO_RETURN.
        int bytes = SSL_read(ssl, buf, BUF_SIZE - 1);
        if (bytes <= 0) {
            fprintf(stderr, "[-] Read failed: ");
            ERR_print_errors_fp(stderr);
            break;
        }

        const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);

        buf[bytes] = '\0';
        printf("[+] Client msg: %s\n", buf);

        /* Simple command-based responses */
        if (strstr(buf, "What is TLS?")) {
            snprintf(reply, BUF_SIZE, "TLS is a protocol for secure network communication.");
        } else if (strstr(buf, "What ciphers are used?")) {
            snprintf(reply, BUF_SIZE, "TLS 1.3 uses ciphers like %s.", SSL_CIPHER_get_name(cipher));
        } else if (strstr(buf, "Is it quantum-safe?")) {
            snprintf(reply, BUF_SIZE, "OQS provider adds quantum-safe protocols.");
        } else if (strstr(buf, "How fast is TLS 1.3?")) {
            snprintf(reply, BUF_SIZE, "TLS 1.3 uses 1-RTT for faster handshake.");
        } else if (strstr(buf, "Exit")) {
            snprintf(reply, BUF_SIZE, "Bye!");
			// ADVANCED: Check return value and SSL_get_error(); 
			// consider partial writes in non-blocking scenarios.
            SSL_write(ssl, reply, strlen(reply));
            break;
        } else {
            snprintf(reply, BUF_SIZE, "I DO NOT UNDERSTAND YOUR MESSAGE: %.989s", buf);
        }

#ifdef _WIN32
        /* Intentionally wait before sending reply.
         * Demonstrates that multiple clients are
         * processed in parallel (concurrency). */
        Sleep(DELAY * 1000);
#else
        sleep(DELAY);
#endif
		// ADVANCED: Check return value and SSL_get_error(); 
		// consider partial writes in non-blocking scenarios.
        if (SSL_write(ssl, reply, strlen(reply)) <= 0) {
            fprintf(stderr, "[-] Write failed\n");
            ERR_print_errors_fp(stderr);
            break;
        }
        printf("[+] Sent: %s\n", reply);
        msg_count++;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    CLOSESOCKET(sock);
}

/* Thread entry point for handling one client */
THREAD_RETURN client_thread(void *arg) {
    ClientData data = *(ClientData *)arg;
    routine(data);
    return THREAD_RETURN_VALUE;
}


/* ------------------------------------------------------------------
 * MAIN FUNCTION
 * ------------------------------------------------------------------*/

int main(int argc, char **argv) {
    if (argc != 4) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
	
	// ADVANCED: Prefer strtol() with range checks for robust parsing.
    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535)
        port = PORT;
    const char *pem = argv[2];
    const char *key = argv[3];

    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    OSSL_PROVIDER *def_prov = OSSL_PROVIDER_load(NULL, "default");
    if (!def_prov) {
        fprintf(stderr, "Default provider load failed\n");
        return EXIT_FAILURE;
    }

    SSL_CTX *ctx = init_ctx();
    if (!ctx) {
        OSSL_PROVIDER_unload(def_prov);
        return EXIT_FAILURE;
    }

    load_certs(ctx, pem, key);
    int sock = make_sock(port);
    if (sock == FAIL) {
        SSL_CTX_free(ctx);
        OSSL_PROVIDER_unload(def_prov);
        return EXIT_FAILURE;
    }

    printf("[+] Waiting for connections...\n");
    while (1) {
        struct sockaddr_in addr;
        SOCKLEN_T len = sizeof(addr);
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client == FAIL) {
            perror("Accept failed");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "[-] SSL creation failed\n");
            CLOSESOCKET(client);
            continue;
        }

        if (SSL_set1_groups_list(ssl, GROUPS) != OK) {
            fprintf(stderr, "[-] KEX/KEM groups failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            CLOSESOCKET(client);
            continue;
        }

        SSL_set_fd(ssl, client);

        ClientData data;
        data.ssl  = ssl;
        data.sock = client;
        data.addr = addr;

        THREAD_TYPE thread;
        if (!THREAD_CREATE(thread, NULL, client_thread, (void *)&data)) {
            fprintf(stderr, "[-] Thread creation failed\n");
            SSL_free(ssl);
            CLOSESOCKET(client);
            continue;
        }

#ifdef __unix__
        pthread_detach(thread);
#else
        CloseHandle(thread);
#endif
    }

    CLOSESOCKET(sock);
    SSL_CTX_free(ctx);
    OSSL_PROVIDER_unload(def_prov);
#ifdef _WIN32
    WSACleanup();
#endif
    return EXIT_SUCCESS;
}
