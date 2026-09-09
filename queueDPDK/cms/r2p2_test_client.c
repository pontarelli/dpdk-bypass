/*
 * Minimal standalone R2P2 test client: plain UDP socket, no dependency on
 * the r2p2 library (avoids needing libconfig-dev / /etc/r2p2.conf, unlike
 * r2p2/linux-apps/linux-client.c). Speaks just enough of the R2P2 wire
 * format (r2p2/r2p2/inc/r2p2/api-internal.h's struct r2p2_header) to send
 * one single-packet request to the R2P2_ECHO or R2P2_STSS application
 * running in queueDPDK/cms's "dol" and print the response.
 *
 * Build:
 *   gcc -O2 -Wall -o r2p2_test_client r2p2_test_client.c
 *
 * Usage:
 *   ./r2p2_test_client echo <server_ip> <server_port> "<message>"
 *   ./r2p2_test_client stss <server_ip> <server_port> <spin_us> <req_size> <rep_size>
 */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#pragma pack(push, 1)
struct r2p2_header {
	uint8_t magic;
	uint8_t header_size;
	uint8_t type_policy;
	uint8_t flags;
	uint16_t rid;
	uint16_t p_order;
};
#pragma pack(pop)

#define R2P2_MAGIC 0xCC
#define R2P2_F_FLAG 0x80
#define R2P2_L_FLAG 0x40
#define R2P2_REQUEST_MSG 0

static int send_request(int fd, struct sockaddr_in *server, const void *payload,
						size_t payload_len, void *reply_buf, size_t reply_buf_len)
{
	uint8_t pkt[2048];
	struct r2p2_header *hdr = (struct r2p2_header *)pkt;
	ssize_t n;
	struct timeval tv = {.tv_sec = 5, .tv_usec = 0};

	if (payload_len + sizeof(*hdr) > sizeof(pkt)) {
		fprintf(stderr, "payload too big for this simple client (single packet only)\n");
		return -1;
	}

	hdr->magic = R2P2_MAGIC;
	hdr->header_size = sizeof(*hdr);
	hdr->type_policy = (R2P2_REQUEST_MSG << 4); // policy nibble = 0 (LB_ROUTE), ignored by our server
	hdr->flags = R2P2_F_FLAG | R2P2_L_FLAG;     // single packet: both first and last
	hdr->rid = htons(1);
	hdr->p_order = htons(1);                    // total packet count for the first packet
	memcpy(pkt + sizeof(*hdr), payload, payload_len);

	if (sendto(fd, pkt, sizeof(*hdr) + payload_len, 0, (struct sockaddr *)server,
			  sizeof(*server)) < 0) {
		perror("sendto");
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	n = recvfrom(fd, pkt, sizeof(pkt), 0, NULL, NULL);
	if (n < 0) {
		perror("recvfrom (timeout after 5s?)");
		return -1;
	}
	if ((size_t)n < sizeof(*hdr)) {
		fprintf(stderr, "reply too short (%zd bytes)\n", n);
		return -1;
	}

	n -= sizeof(*hdr);
	if ((size_t)n > reply_buf_len)
		n = reply_buf_len;
	memcpy(reply_buf, pkt + sizeof(*hdr), n);
	return (int)n;
}

static int make_socket(struct sockaddr_in *server, const char *ip, int port)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(1);
	}
	memset(server, 0, sizeof(*server));
	server->sin_family = AF_INET;
	server->sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &server->sin_addr) != 1) {
		fprintf(stderr, "invalid IP '%s'\n", ip);
		exit(1);
	}
	return fd;
}

static int64_t now_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (int64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static void usage(const char *prog)
{
	fprintf(stderr,
			"Usage:\n"
			"  %s echo <server_ip> <server_port> \"<message>\"\n"
			"  %s stss <server_ip> <server_port> <spin_us> <req_size> <rep_size>\n",
			prog, prog);
	exit(1);
}

int main(int argc, char **argv)
{
	struct sockaddr_in server;
	int fd;

	if (argc < 2)
		usage(argv[0]);

	if (!strcmp(argv[1], "echo")) {
		char reply[1024] = {0};
		int n;

		if (argc != 5)
			usage(argv[0]);
		fd = make_socket(&server, argv[2], atoi(argv[3]));

		n = send_request(fd, &server, argv[4], strlen(argv[4]), reply, sizeof(reply) - 1);
		if (n < 0)
			return 1;
		printf("Received %d bytes: \"%.*s\"\n", n, n, reply);

	} else if (!strcmp(argv[1], "stss")) {
		int64_t req[3]; // spin_us, req_size, rep_size
		uint8_t *payload;
		size_t payload_len;
		char *reply;
		int64_t t0, t1;
		int n;

		if (argc != 7)
			usage(argv[0]);
		fd = make_socket(&server, argv[2], atoi(argv[3]));
		req[0] = atoll(argv[4]); // spin_us
		req[1] = atoll(argv[5]); // req_size
		req[2] = atoll(argv[6]); // rep_size

		payload_len = sizeof(req) + req[1];
		payload = malloc(payload_len);
		memcpy(payload, req, sizeof(req));
		memset(payload + sizeof(req), 'y', req[1]); // padding, content irrelevant

		reply = malloc(sizeof(int64_t) + req[2] + 16);

		t0 = now_us();
		n = send_request(fd, &server, payload, payload_len, reply, sizeof(int64_t) + req[2]);
		t1 = now_us();
		if (n < 0)
			return 1;

		if (n < (int)sizeof(int64_t)) {
			fprintf(stderr, "reply too short for STSS format (%d bytes)\n", n);
			return 1;
		}
		int64_t rep_size_echoed;
		memcpy(&rep_size_echoed, reply, sizeof(rep_size_echoed));
		printf("Round-trip: %ld us (requested spin: %ld us)\n", (long)(t1 - t0), (long)req[0]);
		printf("Reply announced rep_size=%ld, actually received %d payload bytes\n",
			  (long)rep_size_echoed, n - (int)sizeof(int64_t));

		free(payload);
		free(reply);
	} else {
		usage(argv[0]);
	}

	return 0;
}
