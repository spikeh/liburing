/* SPDX-License-Identifier: MIT */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <error.h>

#include "liburing.h"

#define IORING_OP_RECV_ZC	(IORING_OP_URING_CMD + 3)

#define QUEUE_DEPTH 64
#define POOL_PAGES 2048
#define PAGE_SIZE 4096

#define CQ_ENTRIES 512

struct ctx {
	struct io_uring		ring;
	unsigned char		*pool_base;

	void			*ring_ptr;
	size_t			ring_sz;
	struct io_uring_rbuf_rq rq_ring;
	struct io_uring_rbuf_cq cq_ring;
};

unsigned cq_ready(struct io_uring_rbuf_cq *ring)
{
	return io_uring_smp_load_acquire(ring->ktail) - *ring->khead;
}

void cq_advance(struct io_uring_rbuf_cq *ring, unsigned nr)
{
	if (nr)
		io_uring_smp_store_release(ring->khead, *ring->khead + nr);
}

static bool get_sqe(struct ctx *ctx, struct io_uring_sqe **sqe)
{
	*sqe = io_uring_get_sqe(&ctx->ring);

	if (!*sqe) {
		io_uring_submit(&ctx->ring);
		*sqe = io_uring_get_sqe(&ctx->ring);
	}

	if (!*sqe) {
		fprintf(stderr, "get_sqe: failed\n");
		return true;
	}

	return false;
}

static int setup_socket()
{
	int fd, ret;
	int one = 1;

	struct sockaddr_in6 serv_addr6;
	struct sockaddr* paddr;
	size_t paddrlen;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0)
		error(1, errno, "socket creation");

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (ret)
		error(1, errno, "setsocketopt");

	memset(&serv_addr6, 0, sizeof(serv_addr6));
	serv_addr6.sin6_family = AF_INET6;
	serv_addr6.sin6_port = htons(9999);
	serv_addr6.sin6_addr = in6addr_any;
	paddr = (struct sockaddr*)&serv_addr6;
	paddrlen = sizeof(serv_addr6);

	ret = bind(fd, paddr, paddrlen);
	if (ret)
		error(1, errno, "bind");

	ret = listen(fd, 1);
	if (ret)
		error(1, errno, "listen");

	return fd;
}

static void setup_ctx(struct ctx *ctx)
{
	unsigned flags;
	int ret;

	flags = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN;

	ret = io_uring_queue_init(QUEUE_DEPTH, &ctx->ring, flags);
	if (ret < 0)
		error(1, -ret, "io_uring_queue_init");
}

static void clean_ctx(struct ctx *ctx)
{
	munmap(ctx->ring_ptr, ctx->ring_sz);
	io_uring_queue_exit(&ctx->ring);
}

static void setup_pool(struct ctx *ctx)
{
	struct iovec iov;
	size_t size;
	void *pool;
	int ret;

	size = POOL_PAGES * PAGE_SIZE;
	pool = mmap(NULL, size, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	if (pool == MAP_FAILED)
		error(1, errno, "pool mmap");

	iov.iov_base = pool;
	iov.iov_len = size;
	ret = io_uring_register_buffers(&ctx->ring, &iov, 1);
	if (ret)
		error(1, -ret, "pool io_uring_register_buffers");

	ctx->pool_base = pool;
}

static void register_ifq(struct ctx *ctx)
{
	int ifindex, ret;

	ifindex = if_nametoindex("eth0");
	if (!ifindex)
		error(1, 0, "interface does not exist: eth0");

	struct io_uring_zc_rx_ifq_reg reg = {
		.if_idx = ifindex,
		.if_rxq_id = 1,
		.region_id = 0,
		.rq_entries = 4096,
		.cq_entries = 4096,
	};

	ret = io_uring_register_ifq(&ctx->ring, ifindex, 1, 0, &reg);
	if (ret)
		error(1, -ret, "io_uring_register_ifq");

	ctx->ring_ptr = mmap(0, reg.mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ctx->ring.enter_ring_fd, IORING_OFF_RBUF_RING);
	if (ctx->ring_ptr == MAP_FAILED)
		fprintf(stderr, "----- register_ifq: mmap failed, %s\n", strerror(errno));
	ctx->ring_sz = reg.mmap_sz;

	ctx->rq_ring.khead = ctx->ring_ptr + reg.rq_off.head;
	ctx->rq_ring.ktail = ctx->ring_ptr + reg.rq_off.tail;
	ctx->rq_ring.rqes = ctx->ring_ptr + reg.rq_off.rqes;
	ctx->rq_ring.rq_tail = 0;
	ctx->rq_ring.ring_entries = reg.rq_entries;

	ctx->cq_ring.khead = ctx->ring_ptr + reg.cq_off.head;
	ctx->cq_ring.ktail = ctx->ring_ptr + reg.cq_off.tail;
	ctx->cq_ring.cqes = ctx->ring_ptr + reg.cq_off.cqes;
	ctx->cq_ring.ring_entries = reg.cq_entries;
}

static int wait_accept(struct ctx *ctx, int fd)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	if (get_sqe(ctx, &sqe))
		error(1, 0, "wait_accept: get sqe");

	io_uring_prep_accept(sqe, fd, NULL, NULL, 0);
	printf("----- wait_accept: submit\n");
	ret = io_uring_submit(&ctx->ring);
	if (ret == -1)
		error(1, 0, "wait_accept: submit");

	printf("----- wait_accept: wait_cqe\n");
	ret = io_uring_wait_cqe(&ctx->ring, &cqe);
	if (ret)
		error(1, 0, "wait_accept: wait");

	if (cqe->flags & IORING_CQE_F_NOTIF)
		error(1, 0, "driver stalled due to undersized backing store");

	io_uring_cqe_seen(&ctx->ring, cqe);
	printf("----- wait_accept: cqe_seen\n");

	return cqe->res;
}

static int add_recvzc(struct ctx *ctx, int fd)
{
	struct io_uring_sqe *sqe;
	__u64 readlen;

	if (get_sqe(ctx, &sqe)) {
		fprintf(stderr, "add_recvzc: get_sqe failed\n");
		return 1;
	}

	/* op, sqe, fd, addr, len, offset */
	io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, fd, NULL, 0, 0);

	readlen = 800000;
	sqe->addr3 = (readlen << 32);
	sqe->ioprio |= IORING_RECV_MULTISHOT;

	io_uring_sqe_set_data64(sqe, 0xfaceb00c);

	return 0;
}

static int process_cqe(struct ctx *ctx, struct io_uring_cqe *cqe, int fd)
{
	int ret, idx;

	if (!cqe->user_data && !cqe->flags) {
		fprintf(stderr, "process_cqe: ignoring bad cqe\n");
		return 0;
	}

	if (!(cqe->flags & IORING_CQE_F_MORE)) {
		printf("----- process_cqe: add recvzc\n");
		ret = add_recvzc(ctx, fd);
		if (ret)
			return ret;
	}

	if (cqe->res == 0) {
		printf("<!> EOF, flags:%x res:%x\n", cqe->flags, cqe->res);
		return 1;
	}

	if (cqe->res == -ENOBUFS)
		return 0;

	if (cqe->res < 0) {
		error(0, -cqe->res, "process_cqe cqe error");
		if (cqe->res == -EFAULT || cqe->res == -EINVAL)
			fprintf(stderr,
				"NB: This requires a kernel version >= 6.0\n");
		return 1;
	}

	printf("----- process_cqe: cqe res=%d\n", cqe->res);

	unsigned count = cq_ready(&ctx->cq_ring);
	unsigned cq_head = *ctx->cq_ring.khead;
	unsigned cq_mask = ctx->cq_ring.ring_entries - 1;
	unsigned cq_last = cq_head + count;
	printf("----- process_cqe: completion ring count=%d, head=%d, mask=0x%x, last=%d\n", count, cq_head, cq_mask, cq_last);
	int i = 0;
	struct io_uring_rbuf_cqe *buf;
	struct io_uring_rbuf_rqe *rbuf;

	unsigned rq_head = IO_URING_READ_ONCE(*ctx->rq_ring.khead);
	unsigned rq_next = ctx->rq_ring.rq_tail + 1;
	if (rq_next - rq_head > ctx->rq_ring.ring_entries) {
		// TODO: store in cache?
	}

	unsigned rq_mask = ctx->rq_ring.ring_entries - 1;
	printf("----- process_cqe: tail=%d, mask=0x%x\n", ctx->rq_ring.rq_tail, rq_mask);

	// for each cq ring entry, get the off + len
	// TODO: only drain min of cq entries and free rq entries
	for (; cq_head != cq_last; cq_head++, i++) {
		buf = &ctx->cq_ring.cqes[(cq_head & cq_mask)];
		printf("---- process_cqe: buf %d: off=%d, len=%d, flags=%d\n", i, buf->off, buf->len, buf->flags);

		// modify the gail
		// TODO: make sure rq ring is not full
		rbuf = &ctx->rq_ring.rqes[(ctx->rq_ring.rq_tail & rq_mask)];
		rbuf->region = buf->region;
		rbuf->off = buf->off;
		rbuf->len = buf->len;
		ctx->rq_ring.rq_tail++;

		//ctx->rq_ring.rqes;
		// get off + len
		//
		// put it back in the refill ring
		// equiv to main sqe is:
		// get sqe
		// modify it
		// submit_and_...?
	}
	// update cq head
	printf("----- process_cqe: advancing cq ring head by %d\n", count);
	cq_advance(&ctx->cq_ring, count);
	// update rq tail
	printf("----- process_cqe: setting rq tail to %d\n", ctx->rq_ring.rq_tail);
	IO_URING_WRITE_ONCE(*ctx->rq_ring.ktail, ctx->rq_ring.rq_tail);

	return 0;
}

int main(int argc, char *argv[])
{
	struct io_uring_cqe *cqes[CQ_ENTRIES];
	unsigned int cqe_count;
	int sockfd, clientfd;
	struct ctx ctx;
	int ret;

	sockfd = setup_socket();

	setup_ctx(&ctx);

	setup_pool(&ctx);

	register_ifq(&ctx);

	clientfd = wait_accept(&ctx, sockfd);

	ret = add_recvzc(&ctx, clientfd);
	if (ret)
		goto cleanup;

	while (true) {
		ret = io_uring_submit_and_wait(&ctx.ring, 1);
		if (ret == -EINTR)
			continue;
		if (ret < 0) {
			fprintf(stderr, "submit and wait failed: %d\n", ret);
			break;
		}

		cqe_count = io_uring_peek_batch_cqe(&ctx.ring, &cqes[0], CQ_ENTRIES);
		for (int i = 0; i < cqe_count; i++) {
			ret = process_cqe(&ctx, cqes[i], clientfd);
			if (ret)
				goto cleanup;
		}
		io_uring_cq_advance(&ctx.ring, cqe_count);
	}
cleanup:
	clean_ctx(&ctx);
	close(sockfd);

	return ret;
}
