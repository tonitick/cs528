#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h> // task2
#include <openssl/hmac.h> // task2
#include <openssl/ssl.h> // task3

// ============================================================
// task2: enc, dec, hmac utils
// ============================================================
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32 // AES-256
#define IV_SIZE 16
#define HMAC_SIZE 32 // SHA-256 HMAC

void handleErrorsSSL(const char* errstr) {
    fprintf(stderr, "%s\n", errstr);
    exit(EXIT_FAILURE);
}

int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                const unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsSSL("EVP_CIPHER_CTX_new() error occured");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrorsSSL("EVP_EncryptInit_ex() error occured");

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrorsSSL("EVP_EncryptUpdate() error occured");
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrorsSSL("EVP_EncryptFinal_ex() error occured");
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
                const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsSSL("EVP_CIPHER_CTX_new() error occured");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrorsSSL("EVP_DecryptInit_ex() error occured");

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrorsSSL("EVP_DecryptUpdate() error occured");
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrorsSSL("EVP_DecryptFinal_ex() error occured");
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void hmac_sha256(const unsigned char *key, const unsigned char *data, int data_len,
                 unsigned char *hmac, unsigned int *hmac_len) {
    HMAC_CTX ctx;

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, AES_KEY_SIZE, EVP_sha256(), NULL);
    HMAC_Update(&ctx, data, data_len);
    HMAC_Final(&ctx, hmac, hmac_len);
    HMAC_CTX_cleanup(&ctx);
}

// test function
// int main() {
//     // AES key and IV
//     unsigned char key[AES_KEY_SIZE] = "0123456789abcdef0123456789abcdef";
//     unsigned char iv[IV_SIZE] = "0123456789abcdef";

//     // Plaintext to be encrypted
//     unsigned char plaintext[] = "Hello, AES encryption!";
//     int plaintext_len = strlen((char *)plaintext);

//     // Allocate memory for ciphertext (including padding)
//     unsigned char ciphertext[plaintext_len + AES_BLOCK_SIZE];

//     // Encrypt the plaintext
//     int ciphertext_len = aes_encrypt(plaintext, plaintext_len, key, iv, ciphertext);
//     printf("Ciphertext (%d bytes): ", ciphertext_len);
//     for (int i = 0; i < ciphertext_len; ++i)
//         printf("%02x", ciphertext[i]);
//     printf("\n");

//     // Allocate memory for decrypted text
//     unsigned char decryptedtext[ciphertext_len];

//     // Decrypt the ciphertext
//     int decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
//     decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text

//     // Output the decrypted text
//     printf("Decrypted text: %s\n", decryptedtext);

//     // Calculate HMAC for the ciphertext
//     unsigned char hmac[HMAC_SIZE];
//     hmac_sha256(key, ciphertext, ciphertext_len, hmac);
//     printf("HMAC: ");
//     for (int i = 0; i < HMAC_SIZE; ++i)
//         printf("%02x", hmac[i]);
//     printf("\n");

//     return 0;
// }

// ============================================================
// task3: key exchange, close ssl connection utils
// ============================================================
#define REQ_SIZE 6 // "hello", "keyiv", "close"
void ssl_hello_request(SSL *ssl) {
    const char* request = "hello";
    SSL_write(ssl, request, REQ_SIZE);

    // Receive response from server
    char buffer[1024];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[SSL RES] Received: %s\n", buffer);
    }
}

void ssl_hello_response(SSL *ssl) {
    char req[REQ_SIZE];
    int bytes = SSL_read(ssl, req, REQ_SIZE);
    if (bytes > 0) {
        req[bytes] = '\0';
        printf("[SSL REQ] Received: %s\n", req);
    }
    if (strcmp(req, "hello") != 0) return;

    // Send response to client
    const char *response = "Hello from server!";
    SSL_write(ssl, response, strlen(response));
}

void ssl_keyiv_request(SSL *ssl, unsigned char* key, unsigned char* iv) {
    const char* request = "keyiv";
    SSL_write(ssl, request, REQ_SIZE);

    RAND_bytes(key, AES_KEY_SIZE);
    RAND_bytes(iv, IV_SIZE);

    SSL_write(ssl, key, AES_KEY_SIZE);
    SSL_write(ssl, iv, IV_SIZE);

    // Receive response from server
    char buffer[1024];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes > 0) {
        buffer[bytes] = '\0';
        if (strcmp(buffer, "keyiv succeed") != 0) {
            handleErrorsSSL("ssl keyiv_request() error occured");
        }
        else {
            printf("[SSL RES] Received: %s\n", buffer);
            printf("[Client] update key: 0x");
            int i;
            for (i = 0; i < AES_KEY_SIZE; i++) {
                printf("%02x", *((unsigned char*)key + i));
            }
            printf("\n");
            printf("[Client] update iv: 0x");
            for (i = 0; i < IV_SIZE; i++) {
                printf("%02x", *((unsigned char*)iv + i));
            }
            printf("\n");
        }
    }
}

void ssl_keyiv_response(SSL *ssl, unsigned char* key, unsigned char* iv) {
    char req[REQ_SIZE];
    int bytes = SSL_read(ssl, req, REQ_SIZE);
    if (bytes > 0) {
        req[bytes] = '\0';
        printf("[SSL REQ] Received: %s\n", req);
    }
    if (strcmp(req, "keyiv") != 0) return;

    SSL_read(ssl, key, AES_KEY_SIZE);
    SSL_read(ssl, iv, IV_SIZE);
    printf("[Server] update key: 0x");
    int i;
    for (i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02x", *((unsigned char*)key + i));
    }
    printf("\n");
    printf("[Server] update iv: 0x");
    for (i = 0; i < IV_SIZE; i++) {
        printf("%02x", *((unsigned char*)iv + i));
    }
    printf("\n");

    // Send response to client
    const char *response = "keyiv succeed";
    SSL_write(ssl, response, strlen(response));
}
