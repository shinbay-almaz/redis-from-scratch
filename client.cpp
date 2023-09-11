#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>

const int32_t k_max_msg = 4096;

static void msg(const char *message) {
		fprintf(stderr, "%s\n", message);
}

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

static int32_t read_full(int fd, char *buf, size_t n) {
		while (n > 0) {
				ssize_t rv = read(fd, buf, n);

				if (rv <= 0) {
						return -1; // error or unexpected EOF
				}

				assert((size_t)rv <= n);
				n -= (size_t)rv;
				buf += rv;
		}
		return 0;
}

static int32_t write_all(int fd, const char *buf, size_t n) {
		while (n > 0) {
				ssize_t rv = write(fd, buf, n);
				if (rv <= 0) {
						return -1; // error 
				}
				assert((size_t)rv <= n);
				n -= (size_t)rv;
				buf += rv;
		}
		return 0;
}

static int32_t send_req(int fd, const std::vector<std::string> &cmd) {
		uint32_t len = 4;
		for (const std::string &s : cmd) {
				len += 4 + s.size();
		}

		if (len > k_max_msg) {
				return -1;
		}

		char wbuf[4 + k_max_msg];
		uint32_t n = cmd.size();
		memcpy(&wbuf[0], &len, 4);
		memcpy(&wbuf[4], &n, 4);
		size_t pos = 8;
		for (const std::string &s : cmd) {
				uint32_t p = (uint32_t)s.size();
				memcpy(&wbuf[pos], &p, 4);
				memcpy(&wbuf[pos + 4], s.data(), s.size());
				pos += 4 + p;
		}

		return write_all(fd, wbuf, 4 + len);
}

static int32_t read_res(int fd) {
		char rbuf[4 + k_max_msg + 1];
		uint32_t len = 0;

		errno = 0;
		int32_t err = read_full(fd, rbuf, 4);
		if (err) {
				if (errno == 0) {
						msg("EOF");
				} else {
						msg("read() error");
				}
				return err;
		}

		memcpy(&len, &rbuf[0], 4);
		if (len > k_max_msg) {
				msg("too long");
				return -1;
		}

		err = read_full(fd, &rbuf[4], len);
		if (err) {
				if (errno == 0) {
						msg("EOF");
				} else {
						msg("read() error");
				}
				return err;
		}

		rbuf[4 + len] = '\0';

		uint32_t rescode = 0;
		if (len < 4) {
				msg("bad response");
				return -1;
		}
		memcpy(&rescode, &rbuf[4], 4);
		printf("server says: [%u] %.*s\n", rescode, len - 4, &rbuf[8]);
		return 0;
}

int main(int argc, char **argv) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);

		struct sockaddr_in addr = {};
		addr.sin_family = AF_INET;
		addr.sin_port = ntohs(1234);
		addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);

		int rv = connect(fd, (const sockaddr *)&addr, sizeof(addr));
		if (rv) {
				die("connect()");
		}
		
		std::vector<std::string> cmd;
		for (int i = 1; i < argc; i++) {
				cmd.push_back(argv[i]);
		}

		int32_t err = send_req(fd, cmd);
		if (err) {
				goto L_DONE;
		}
		err = read_res(fd);
		if (err) {
				goto L_DONE;
		}

	L_DONE:
		close(fd);

		return 0;
}
