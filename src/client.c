#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <inttypes.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "include/config.h"
#include "include/bfw.h"

int SetupSocket(struct config_map *cfg)
{
    // Create socket.
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    // Check to ensure socket is valid.
    if (sock < 1)
    {
        return sock;
    }

    int reuse = 1;

    // Set socket option so we can reuse port.
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0)
    {
        fprintf(stderr, "Error setting option on listen socket :: %s\n", strerror(errno));

        return -1;
    }

    struct sockaddr_in din;

    din.sin_family = AF_INET;
    din.sin_addr.s_addr = inet_addr(cfg->serverip);
    din.sin_port = htons(cfg->serverport);
    memset(&din.sin_zero, 0, sizeof(din.sin_zero));

    // Connect to server.
    if (connect(sock, (struct sockaddr *)&din, sizeof(din)) < 0)
    {
        fprintf(stderr, "Error connecting to backbone :: %s.\n", strerror(errno));

        return -1;
    }

    return sock;
}

void CheckSocket(int *sockfd)
{
    if (sockfd < 1)
    {
        return;
    }

    uint8_t msg = 0x60;

    // Attempt to send a heartbeat (0x60).
    if (send(sockfd, msg, 1, 0) < 1)
    {
        sockfd = -1;

        return;
    }
    // Wait for response.
    char resp[256];

    if (recv(sockfd, resp, sizeof(resp), 0) < 1)
    {
        sockfd = -1;
    }
}

int EncryptAndSend(int sockfd, unsigned char *buff, int len, unsigned char *key, uint64_t *counter, uint8_t header)
{
    unsigned char hash[crypto_generichash_BYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    unsigned char ctext[crypto_aead_chacha20poly1305_IETF_ABYTES + 2048];
    unsigned char scounter[sizeof(uint64_t)];
    unsigned long long ctextlen;

    // Size is sizeof(ctext) + sizeof(uint64_t).
    unsigned char tosend[crypto_aead_chacha20poly1305_IETF_ABYTES + sizeof(buff) + sizeof(uint8_t) + sizeof(uint64_t)];

    // Copy counter integer to string.
    memcpy(scounter, counter, sizeof(uint64_t));

    // Generate hash to use as nonce (first 12 bytes).
    if (crypto_hash_sha256(hash, scounter, sizeof(scounter)) != 0)
    {
        fprintf(stderr, "Error hashing nonce.\n");

        return 1;
    }

    // Copy first 12 bytes of hash to nonce.
    memcpy(nonce, hash, 12);
    
    // Encrypt the message and store in ctext.
    crypto_aead_chacha20poly1305_ietf_encrypt(ctext, &ctextlen, buff, len, NULL, 0, NULL, nonce, key);

    // Check to ensure we can decrypt the message before sending.
    unsigned char decrypted[2048];
    unsigned long long dlen;

    // Attempt to decrypt message using the existing cipher text, nonce/IV, and key before sending to server.
    if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &dlen, NULL, ctext, ctextlen, NULL, 0, nonce, key) != 0)
    {
        fprintf(stderr, "Encrypted message is forged!\n");

        return 1;
    }

    // Copy header (first byte).
    uint8_t *headerpos = tosend;
    memcpy(headerpos, header, 1);

    // Copy counter to tosend (8 bytes).
    char *sendcounter = tosend + 1;
    memcpy(sendcounter, counter, sizeof(uint64_t));

    // Copy cipher text to rest of string.
    char *ctextptr = (tosend + 1) + sizeof(uint64_t);
    memcpy(ctextptr, ctext, ctextlen);

    // Send message.
    if (write(sockfd, tosend, ctextlen + sizeof(uint64_t)) < 1)
    {
        fprintf(stderr, "Error sending packet on socket :: %s\n", strerror(errno));

        return 1;
    }

    // Increment counter.
    *counter++;

    return 0;
}

int Decrypt(unsigned char *msg, int len, unsigned char *out, unsigned long long *dlen, unsigned char *key, uint8_t *header)
{
    // Check length and ensure it's at least 9 bytes (header + counter).
    if (len < 9)
    {
        return 1;
    }

    unsigned char ctext[crypto_aead_chacha20poly1305_IETF_ABYTES + MAX_SEND_LENGTH];
    unsigned char hash[crypto_generichash_BYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    uint64_t counter;

    // First get the header and assign it to the header pointer for use outside of function if needed.
    uint8_t *headerpos = msg;
    memcpy(header, headerpos, 1);

    // Now get counter.
    uint64_t *counterpos = msg + sizeof(uint8_t);
    memcpy(&counter, counterpos, sizeof(uint64_t));

    // Store rest of message as cipher text.
    unsigned char *ctextpos = msg + sizeof(uint8_t) + sizeof(uint64_t);
    memcpy(ctext, ctextpos, (len - sizeof(uint8_t) - sizeof(uint64_t)));

    // Generate hash based off of counter in SHA256.
    if (crypto_hash_sha256(hash, (unsigned char *)&counter, sizeof(uint64_t)) != 0)
    {
        fprintf(stderr, "Unable to generate hash for nonce.\n");

        return 1;
    }

    // Copy first 12 bytes to nonce.
    memcpy(nonce, hash, 12);

    // Attempt to decrypt.
    if (crypto_aead_chacha20poly1305_ietf_decrypt(out, dlen, NULL, ctext, (len - sizeof(uint8_t) - sizeof(uint64_t)), NULL, 0, nonce, key) != 0)
    {
        fprintf(stderr, "Unable to decrypt message with header %02x.\n", header);

        return 1;
    }

    return 0;
}