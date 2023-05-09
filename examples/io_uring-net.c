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

#if 1
/* XXX temp development hack */
struct io_uring_zctap_iov {
	__u32	off;
	__u32	len;
	__u16	bgid;
	__u16	bid;
	__u16	resv[2];
};

#define IORING_OP_RECV_ZC	(IORING_OP_URING_CMD + 3)
#define PAGE_SIZE		4096
#endif

#define FRAME_REGION_SIZE	(8192 * 4096)
#define FILL_QUEUE_ENTRIES	4096
#define COPY_QUEUE_ENTRIES	256
#define COPY_BUF_SIZE		4096

enum {
	BGID_ZC_REGION,
	BGID_METADATA,
	BGID_COPY_RING,
	BGID_FILL_RING,
};

#define QD 64
#define BUF_SHIFT 12 /* 4k */
#define CQES (QD * 16)
#define BUFFERS CQES
#define CONTROLLEN 0

struct sendmsg_ctx {
	struct msghdr msg;
	struct iovec iov;
};

struct ctx {
	struct io_uring ring;
	struct io_uring_buf_ring *buf_ring;
	struct io_uring_buf_ring *fillq;
	struct io_uring_buf_ring *copyq;
	unsigned char *buffer_base;
	unsigned char *copy_base;
	unsigned char *frame_base;
	struct msghdr msg;
	int buf_shift;
	int af;
	int queue_id;
	int ifq_id;
	int verbose;
	bool udp;
	char *ifname;
	struct sendmsg_ctx send[BUFFERS];
	size_t buf_ring_size;
	size_t fillq_size;
	size_t copyq_size;

	unsigned long copy_bytes;
	unsigned long zc_bytes;
};

static size_t buffer_size(struct ctx *ctx)
{
	return 1U << ctx->buf_shift;
}

static unsigned char *get_buffer(struct ctx *ctx, int idx)
{
	return ctx->buffer_base + (idx << ctx->buf_shift);
}

/* buffer pool for metadata, etc. */
static int setup_buffer_pool(struct ctx *ctx)
{
	int ret, i;
	void *mapped;
	struct io_uring_buf_reg reg;

	/* maps:
	 *	BUFFER x (struct io_ring_buf)
	 *	BUFFER x (buffer_size) (4K, by default)
	 * buffer_ring is first part.
	 * buffer_base is second part.
	 *
	 * register_buf_ring() registers the ring
	 *
	 * buffers are then provided:
	 *   io_uring_buf_ring_add(ring, addr, len, buf_id)
	 * io_uring_buf_ring_advance(ctx->buf_ring, BUFFERS);
	 */

	ctx->buf_ring_size = (sizeof(struct io_uring_buf) + buffer_size(ctx)) * BUFFERS;
	mapped = mmap(NULL, ctx->buf_ring_size, PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	if (mapped == MAP_FAILED) {
		fprintf(stderr, "buf_ring mmap: %s\n", strerror(errno));
		return -1;
	}
	ctx->buf_ring = (struct io_uring_buf_ring *)mapped;

	io_uring_buf_ring_init(ctx->buf_ring);

	reg = (struct io_uring_buf_reg) {
		.ring_addr = (unsigned long)ctx->buf_ring,
		.ring_entries = BUFFERS,
		.bgid = BGID_METADATA,
	};
	ctx->buffer_base = (unsigned char *)ctx->buf_ring +
			   sizeof(struct io_uring_buf) * BUFFERS;
	printf("metadata base region: %p, group %d\n",
		ctx->buffer_base, BGID_METADATA);

	ret = io_uring_register_buf_ring(&ctx->ring, &reg, 0);
	if (ret) {
		fprintf(stderr, "buf_ring init failed: %s\n"
				"NB This requires a kernel version >= 6.0\n",
				strerror(-ret));
		return ret;
	}

	for (i = 0; i < BUFFERS; i++) {
		io_uring_buf_ring_add(ctx->buf_ring, get_buffer(ctx, i), buffer_size(ctx), i,
				      io_uring_buf_ring_mask(BUFFERS), i);
	}
	io_uring_buf_ring_advance(ctx->buf_ring, BUFFERS);

	return 0;
}

/* fill queue used for returning packet store buffers. */
static int setup_fill_queue(struct ctx *ctx)
{
	struct io_uring_buf_reg reg;
	void *area;
	int ret;

	ctx->fillq_size = sizeof(struct io_uring_buf) * FILL_QUEUE_ENTRIES;
	area = mmap(NULL, ctx->fillq_size, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	if (area == MAP_FAILED)
		error(1, errno, "fill queue mmap");

	ctx->fillq = (struct io_uring_buf_ring *)area;

	io_uring_buf_ring_init(ctx->fillq);

	reg = (struct io_uring_buf_reg) {
		.ring_addr = (unsigned long)ctx->fillq,
		.ring_entries = FILL_QUEUE_ENTRIES,
		.bgid = BGID_FILL_RING,
	};

	/* flags is unused */
	ret = io_uring_register_buf_ring(&ctx->ring, &reg, 0);
	if (ret) {
		error(0, -ret, "fillq register failed");
		fprintf(stderr, "NB This requires a kernel version >= 6.0\n");
		exit(1);
	}

	return 0;
}

/* copy pool for system pages. */
static int setup_copy_pool(struct ctx *ctx)
{
	struct io_uring_buf_reg reg;
	void *area;
	int i, ret;

	ctx->copyq_size = (sizeof(struct io_uring_buf) + COPY_BUF_SIZE) *
			  COPY_QUEUE_ENTRIES;
	area = mmap(NULL, ctx->copyq_size, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	if (area == MAP_FAILED)
		error(1, errno, "coyp queue mmap");

	ctx->copyq = (struct io_uring_buf_ring *)area;

	io_uring_buf_ring_init(ctx->copyq);

	reg = (struct io_uring_buf_reg) {
		.ring_addr = (unsigned long)ctx->copyq,
		.ring_entries = COPY_QUEUE_ENTRIES,
		.bgid = BGID_COPY_RING,
	};

	/* flags is unused */
	ret = io_uring_register_buf_ring(&ctx->ring, &reg, 0);
	if (ret)
		error(1, -ret, "copyq ring register failed");

	area += sizeof(struct io_uring_buf) * COPY_QUEUE_ENTRIES;
	ctx->copy_base = area;
	printf("copy base region: %p, group %d\n", area, BGID_COPY_RING);

	for (i = 0; i < COPY_QUEUE_ENTRIES; i++) {
		io_uring_buf_ring_add(ctx->copyq, area + i * COPY_BUF_SIZE,
			COPY_BUF_SIZE, i,
			io_uring_buf_ring_mask(COPY_QUEUE_ENTRIES), i);
	}
	io_uring_buf_ring_advance(ctx->copyq, COPY_QUEUE_ENTRIES);

	return 0;
}

static int setup_context(struct ctx *ctx)
{
	struct io_uring_params params;
	int ret;

	memset(&params, 0, sizeof(params));
	params.cq_entries = QD * 8;
	params.flags = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN |
		       IORING_SETUP_CQSIZE;

	ret = io_uring_queue_init_params(QD, &ctx->ring, &params);
	if (ret < 0) {
		fprintf(stderr, "queue_init failed: %s\n"
				"NB: This requires a kernel version >= 6.0\n",
				strerror(-ret));
		return ret;
	}

	ret = setup_buffer_pool(ctx);
	if (ret)
		io_uring_queue_exit(&ctx->ring);

	memset(&ctx->msg, 0, sizeof(ctx->msg));
	ctx->msg.msg_namelen = sizeof(struct sockaddr_storage);
	ctx->msg.msg_controllen = CONTROLLEN;
	return ret;
}

static int setup_sock(struct ctx *ctx, int port)
{
	int ret;
	int fd;
	uint16_t nport = port <= 0 ? 0 : htons(port);
	int one = 1;
	int flags = 0; /* SOCK_NONBLOCK */

	if (ctx->udp)
		fd = socket(ctx->af, SOCK_DGRAM | flags, IPPROTO_UDP);
	else
		fd = socket(ctx->af, SOCK_STREAM | flags, IPPROTO_TCP);
	if (fd < 0) {
		fprintf(stderr, "sock_init: %s\n", strerror(errno));
		return -1;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (ret) {
		fprintf(stderr, "setsockopt: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	if (ctx->af == AF_INET6) {
		struct sockaddr_in6 addr6 = {
			.sin6_family = ctx->af,
			.sin6_port = nport,
			.sin6_addr = IN6ADDR_ANY_INIT
		};

		ret = bind(fd, (struct sockaddr *) &addr6, sizeof(addr6));
	} else {
		struct sockaddr_in addr = {
			.sin_family = ctx->af,
			.sin_port = nport,
			.sin_addr = { INADDR_ANY }
		};

		ret = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
	}

	if (ret) {
		fprintf(stderr, "sock_bind: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	if (port <= 0) {
		int port;
		struct sockaddr_storage s;
		socklen_t sz = sizeof(s);

		if (getsockname(fd, (struct sockaddr *)&s, &sz)) {
			fprintf(stderr, "getsockname failed\n");
			close(fd);
			return -1;
		}

		port = ntohs(((struct sockaddr_in *)&s)->sin_port);
		fprintf(stderr, "port bound to %d\n", port);
	}

	if (!ctx->udp) {
		ret = listen(fd, 1);
		if (ret) {
			fprintf(stderr, "listen: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
	}

	return fd;
}

static void cleanup_context(struct ctx *ctx)
{
	munmap(ctx->buf_ring, ctx->buf_ring_size);
	io_uring_queue_exit(&ctx->ring);
}

static bool get_sqe(struct ctx *ctx, struct io_uring_sqe **sqe)
{
	*sqe = io_uring_get_sqe(&ctx->ring);

	if (!*sqe) {
		io_uring_submit(&ctx->ring);
		*sqe = io_uring_get_sqe(&ctx->ring);
	}
	if (!*sqe) {
		fprintf(stderr, "cannot get sqe\n");
		return true;
	}
	return false;
}

static int wait_accept(struct ctx *ctx, int fd, int *clientfd)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	if (get_sqe(ctx, &sqe))
		return -1;

	io_uring_prep_accept(sqe, fd, NULL, NULL, 0);
	ret = io_uring_submit(&ctx->ring);
	if (ret == -1) {
		fprintf(stderr, "cannot submit accept\n");
		return true;
	}

	ret = io_uring_wait_cqe(&ctx->ring, &cqe);
	if (ret) {
		fprintf(stderr, "accept wait_cqe\n");
		return true;
	}
	*clientfd = cqe->res;
	io_uring_cqe_seen(&ctx->ring, cqe);

	return false;
}

/* adds one SQE for RECVMSG, as multishot */
static int add_recv(struct ctx *ctx, int idx)
{
	struct io_uring_sqe *sqe;

	if (get_sqe(ctx, &sqe))
		return -1;

	io_uring_prep_recvmsg_multishot(sqe, idx, &ctx->msg, MSG_TRUNC);
	sqe->flags |= IOSQE_FIXED_FILE;

	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = 1;
	io_uring_sqe_set_data64(sqe, BUFFERS + 1);
	return 0;
}

/* adds one SQE for RECVZC */
static int add_recvzc(struct ctx *ctx, int idx_sockfd)
{
	struct io_uring_sqe *sqe;
	__u64 readlen, copy_bgid;

	if (get_sqe(ctx, &sqe))
		return -1;

	/* API for RECV_ZC:
	 *  fd		= sockfd (or registered file index)
	 *  addr/len	= immediate metadata buffer.
	 *		  not used if BUFFER_SELECT flag is set.
	 *  buf_group	= group to obtain metadata buffer if BUFFER_SELECT.
	 *  ioprio	= io_uring recvmsg flags (aka MULTISHOT)
	 *  msg_flags	= recvmsg flags (MSG_DONTWAIT, etc)
	 *  addr3	= <32>data_len | <16>copy_bgid | <ifq_id> 
	 */

	/* op, sqe, fd, addr, len, offset */
	io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, idx_sockfd, NULL, 0, 0);
	sqe->flags |= IOSQE_FIXED_FILE;

	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = BGID_METADATA;

	readlen = 800000;
	copy_bgid = BGID_COPY_RING;
	sqe->addr3 = (readlen << 32) | (copy_bgid << 16) | ctx->ifq_id;
//	printf("setting addr3: %llx\n", sqe->addr3);

	io_uring_sqe_set_data64(sqe, BUFFERS + 1);

	return 0;
}

static void recycle_bgid(struct ctx *ctx, int bgid, int idx)
{
	struct io_uring_buf_ring *ring;
	void *addr;

	switch (bgid) {
	case BGID_METADATA:
		ring = ctx->buf_ring;
		io_uring_buf_ring_add(ring,
			get_buffer(ctx, idx), buffer_size(ctx), idx,
			io_uring_buf_ring_mask(BUFFERS), 0);
		break;
	case BGID_COPY_RING:
		ring = ctx->copyq;
		addr = ctx->copy_base + (idx * COPY_BUF_SIZE);
		io_uring_buf_ring_add(ring,
			addr, COPY_BUF_SIZE, idx,
			io_uring_buf_ring_mask(COPY_QUEUE_ENTRIES), 0);
		break;
	case BGID_ZC_REGION:
	case BGID_FILL_RING:
		ring = ctx->fillq;
		addr = (void *)(((uintptr_t)bgid << 16) | idx);
		io_uring_buf_ring_add(ring,
			addr, PAGE_SIZE, idx,
			io_uring_buf_ring_mask(FILL_QUEUE_ENTRIES), 0);
		break;
	default:
		error(1, 0, "unknown bgid %d\n", bgid);
		return;
	}
	io_uring_buf_ring_advance(ring, 1);
}

static void recycle_buffer(struct ctx *ctx, int idx)
{
	io_uring_buf_ring_add(ctx->buf_ring, get_buffer(ctx, idx), buffer_size(ctx), idx,
			      io_uring_buf_ring_mask(BUFFERS), 0);
	io_uring_buf_ring_advance(ctx->buf_ring, 1);
}

static int process_cqe_send(struct ctx *ctx, struct io_uring_cqe *cqe)
{
	int idx = cqe->user_data;

	if (cqe->res < 0)
		fprintf(stderr, "bad send %s\n", strerror(-cqe->res));
	recycle_buffer(ctx, idx);
	return 0;
}

static void
hex_dump(void *data, size_t length, int frag)
{
	const unsigned char *address = data;
	const unsigned char *line = address;
	size_t line_size = 16;
	unsigned char c;
	char buf[32];
	int i = 0;

	sprintf(buf, "%9.9d", frag);
	printf("%s | ", buf);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf("| ");	/* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
			if (length > 0)
				printf("%s | ", buf);
		}
	}
	printf("\n");
}

static int process_cqe_recv(struct ctx *ctx, struct io_uring_cqe *cqe,
			    int fdidx)
{
	int ret, idx;
//	struct io_uring_recvmsg_out *o;
//	struct io_uring_sqe *sqe;
	int last_copybuf = -1;

	if (!(cqe->flags & IORING_CQE_F_MORE)) {
		ret = add_recvzc(ctx, fdidx);
		if (ret)
			return ret;
	}

	if (cqe->res == 0) {
		printf("EOF, res:%d flags:%d\n", cqe->res, cqe->flags);
		return 1;
	}

	if (cqe->res == -ENOBUFS)
		return 0;

	if (!(cqe->flags & IORING_CQE_F_BUFFER) || cqe->res < 0) {
		error(0, -cqe->res, "recv cqe");
		if (cqe->res == -EFAULT || cqe->res == -EINVAL)
			fprintf(stderr,
				"NB: This requires a kernel version >= 6.0\n");
		return -1;
	}
	idx = cqe->flags >> 16;

	if (ctx->verbose) {
		/* at the moment, 'res' returned here is # of bytes read */
		printf("user_data: %llx\n", cqe->user_data);
		printf("res (error/buflen): %d\n", cqe->res);
		printf("flags: %x\n", cqe->flags);
	}

	{
		struct io_uring_zctap_iov *zov;
		void *base, *addr;
		int count;
		int i, bufid;

		/* cqe flags contains the buffer index */
		addr = get_buffer(ctx, cqe->flags >> 16);

		count = cqe->res / sizeof(*zov);
		zov = addr;

		if (ctx->verbose) {
			int total = 0;
			for (i = 0; i < count; i++)
				total += zov[i].len;

			printf("Buffer address: %p\n", addr);
			printf("data length: %d, vectors:%d\n", total, count);
		}
		if (ctx->verbose > 1)
			hex_dump(addr, cqe->res, 0);

		for (i = 0; i < count; i++) {
			char *type;
			if (zov[i].bgid == BGID_COPY_RING) {
				base = ctx->copy_base;
				addr = base + zov[i].bid * COPY_BUF_SIZE;
				type = "COPY";
				ctx->copy_bytes += zov[i].len;
			} else {
				/* should be frame area, PAGE_SIZE */
				base = ctx->frame_base;
				addr = base + zov[i].bid * PAGE_SIZE;
				type = "ZC";
				ctx->zc_bytes += zov[i].len;
			}
			if (ctx->verbose)
				printf("%d: g:%d id:%d off:%d len:%d %s\n",
					i, zov[i].bgid, zov[i].bid,
					zov[i].off, zov[i].len, type);
			if (ctx->verbose > 1)
				hex_dump(addr + zov[i].off, zov[i].len, i);

			bufid = zov[i].bid;
			if (zov[i].bgid == BGID_COPY_RING) {
				if (bufid == last_copybuf)
					continue;
				if (last_copybuf == -1) {
					last_copybuf = bufid;
					continue;
				}
			}
			recycle_bgid(ctx, zov[i].bgid, bufid);
		}
	}

	/* copy_buf is not refcounted, and the same buffer may be returned
	 * multiple times in a single recvzc call; but the buffer is not 
	 * shared across multiple calls.
	 */
	if (last_copybuf != -1)
		recycle_bgid(ctx, BGID_COPY_RING, last_copybuf);
	recycle_bgid(ctx, BGID_METADATA, cqe->flags >> 16);

#if 0
	o = io_uring_recvmsg_validate(get_buffer(ctx, cqe->flags >> 16),
				      cqe->res, &ctx->msg);
	if (!o) {
		fprintf(stderr, "bad recvmsg\n");
		return -1;
	}
	if (o->namelen > ctx->msg.msg_namelen) {
		fprintf(stderr, "truncated name\n");
		recycle_buffer(ctx, idx);
		return 0;
	}
	if (o->flags & MSG_TRUNC) {
		unsigned int r;

		r = io_uring_recvmsg_payload_length(o, cqe->res, &ctx->msg);
		fprintf(stderr, "truncated msg need %u received %u\n",
				o->payloadlen, r);
		recycle_buffer(ctx, idx);
		return 0;
	}

	if (io_uring_recvmsg_payload_length(o, cqe->res, &ctx->msg) == 0) {
		fprintf(stderr, "0 byte recv, assuming EOF.\n");
		return -1;
	}

	if (ctx->verbose) {
		char buff[INET6_ADDRSTRLEN + 1];
		const char *name;
		struct sockaddr_in *addr = io_uring_recvmsg_name(o);

		name = inet_ntop(ctx->af, addr, buff, sizeof(buff));
		if (!name)
			name = "<INVALID>";
		fprintf(stderr, "received %u bytes %d from %s:%d\n",
			io_uring_recvmsg_payload_length(o, cqe->res, &ctx->msg),
			o->namelen, name, (int)ntohs(addr->sin_port));
	}

	if (get_sqe(ctx, &sqe))
		return -1;

	ctx->send[idx].iov = (struct iovec) {
		.iov_base = io_uring_recvmsg_payload(o, &ctx->msg),
		.iov_len =
			io_uring_recvmsg_payload_length(o, cqe->res, &ctx->msg)
	};
	ctx->send[idx].msg = (struct msghdr) {
		.msg_namelen = o->namelen,
		.msg_name = io_uring_recvmsg_name(o),
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_iov = &ctx->send[idx].iov,
		.msg_iovlen = 1
	};

	io_uring_prep_sendmsg(sqe, fdidx, &ctx->send[idx].msg, 0);
	io_uring_sqe_set_data64(sqe, idx);
	sqe->flags |= IOSQE_FIXED_FILE;
#endif

	return 0;
}

static int process_cqe(struct ctx *ctx, struct io_uring_cqe *cqe, int fdidx)
{
	if (cqe->user_data < BUFFERS)
		return process_cqe_send(ctx, cqe);
	else
		return process_cqe_recv(ctx, cqe, fdidx);
}

int
io_zctap_ifq(struct ctx *ctx)
{
	int ifindex, bgid, region_id;
	__u16 qid;
	int ret;

	/* API for register_ifq:
	 *  ifindex	- network device index
	 *  qid		- desired/targeted qid
	 *  ifq_id	- slot used for ifq id
	 *  bgid	- fill queue id
	 *  region_id	- index into registered buffer
	 */

	bgid = BGID_FILL_RING;
	qid = ctx->queue_id;
	ctx->ifq_id = 0;
	region_id = BGID_ZC_REGION;

	ifindex = if_nametoindex(ctx->ifname);
	if (!ifindex) {
		fprintf(stderr, "Interface %s does not exist\n", ctx->ifname);
		return -1;
	}
	ret = io_uring_register_ifq(&ctx->ring, ifindex, qid,
				    ctx->ifq_id, bgid, region_id);

	if (ret) {
		fprintf(stderr, "register_ifq failed: %s\n", strerror(-ret));
		return -1;
	}
	fprintf(stderr, "registered ifq:%d, r=%d\n", qid, ret);
	return ret;
}

#if 0
static void
io_complete_sqe(struct io_uring *ring, struct io_uring_sqe *sqe,
		const char *what)
{
	struct io_uring_cqe *cqe;
	int ret;

	ret = io_uring_submit(ring);
	if (ret < 0)
		error(1, -ret, "submit failed");

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret)
		error(1, -ret, "wait_cqe failed");

	if (cqe->res < 0)
		error(1, -cqe->res, "Bad SQE '%s'", what);

	io_uring_cqe_seen(ring, cqe);
}
#endif

int setup_zctap_region(struct ctx *ctx)
{
	struct iovec iov;
	void *area;
	int ret;

	area = mmap(NULL, FRAME_REGION_SIZE, PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	if (area == MAP_FAILED)
		error(1, errno, "frame_region mmap");

	/* register (mmap) this buffer area with the kernel */
	printf("frame base region: %p, group %d\n", area, BGID_ZC_REGION);
	ctx->frame_base = area;

	/* Registers (pins) memory with the kernel.
	 * the region is identified by its position in the iov[] vector.
	 */
	iov.iov_base = area;
	iov.iov_len = FRAME_REGION_SIZE;
	ret = io_uring_register_buffers(&ctx->ring, &iov, 1);
	if (ret)
		error(1, -ret, "register_buffers");

#if 0
	if (get_sqe(ctx, &sqe))
		return -1;

	/* API for provide_ifq_region:
	 *  fd		= network_device index
	 *  area	= mmap'd area
	 *  len		= length of area
	 *
	 * area/len refer to a previously mapped buffer area
	 */
	io_uring_prep_rw(IORING_OP_PROVIDE_IFQ_REGION, sqe, ctx->ifq_id,
			 area, FRAME_REGION_SIZE, 0);

	/* buf_group -> buf_index, selects from user_bufs */
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = 0;

	io_uring_sqe_set_data64(sqe, BUFFERS + 1);

	io_complete_sqe(&ctx->ring, sqe, "ifq region");
#endif

	return 0;
}

unsigned long
now_nsec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

unsigned long
elapsed(unsigned long start)
{
	return now_nsec() - start;
}

#define array_size(x)	(sizeof(x) / sizeof((x)[0]))

const char *
rate(unsigned long bytes, unsigned long nsec, float *rv)
{
	static const char *scale_str[] = {
		"b/s", "Kb/s", "Mb/s", "Gb/s",
	};
	int scale;
	float val;

	val = ((float)bytes / (float)nsec) * 8 * 1000000000UL;
	for (scale = 0; val > 1000; scale++)
		val /= 1000;
	*rv = val;

	if (scale > array_size(scale_str))
		return "unknown";
	return scale_str[scale];
}

void stats(struct ctx *ctx, unsigned long start)
{
	unsigned long interval, total;
	const char *scale;
	float val;

	interval = elapsed(start);
	total = ctx->copy_bytes + ctx->zc_bytes;
	scale = rate(total, interval, &val);

	printf(" copy bytes: %lu\n", ctx->copy_bytes);
	printf("   ZC bytes: %lu\n", ctx->zc_bytes);
	printf("Total bytes: %lu, nsec:%lu\n", total, interval);
	printf("       Rate: %.2f %s\n", val, scale);
}

int main(int argc, char *argv[])
{
	struct ctx ctx = {
		.af		= AF_INET6,
		.buf_shift	= BUF_SHIFT,
		.ifname		= "eth0",
		.queue_id	= -1,
	};
	int ret;
	int port = -1;
	int sockfd, clientfd;
	int opt;
	struct io_uring_cqe *cqes[CQES];
	unsigned int count, i;
	unsigned long start;

	while ((opt = getopt(argc, argv, "46b:i:p:q:uv")) != -1) {
		switch (opt) {
		case '4':
			ctx.af = AF_INET;
			break;
		case '6':
			ctx.af = AF_INET6;
			break;
		case 'b':
			ctx.buf_shift = atoi(optarg);
			break;
		case 'i':
			ctx.ifname = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'q':
			ctx.queue_id = atoi(optarg);
			break;
		case 'u':
			ctx.udp = true;
			break;
		case 'v':
			ctx.verbose++;
			break;
		default:
			fprintf(stderr, "Usage: %s [-4] [-6] [-p port] [-u] "
					"[-i ifname] [-q queue_id] "
					"[-b log2(BufferSize)] [-v]\n",
					argv[0]);
			exit(-1);
		}
	}

	if (ctx.verbose) {
		fprintf(stderr, "%s %s\n", 
			ctx.af == AF_INET ? "IPv4" : "IPv6",
			ctx.udp ? "UDP" : "TCP");
	}

	sockfd = setup_sock(&ctx, port);
	if (sockfd < 0)
		return 1;

	if (setup_context(&ctx)) {
		close(sockfd);
		return 1;
	}

	if (ctx.queue_id != -1) {
		ret = setup_fill_queue(&ctx);
		if (ret)
			return 1;

		ret = setup_zctap_region(&ctx);
		if (ret)
			return 1;

		ret = io_zctap_ifq(&ctx);
		if (ret)
			return 1;
	}

	ret = setup_copy_pool(&ctx);
	if (ret)
		return 1;

	clientfd = sockfd;
	if (!ctx.udp) {
		ret = wait_accept(&ctx, sockfd, &clientfd);
		if (ret) {
			fprintf(stderr, "wait_accept: %s\n", strerror(-ret));
			return -1;
		}
	}

	start = now_nsec();

	/* optimization: register clientfd as file 0, avoiding lookups */
	ret = io_uring_register_files(&ctx.ring, &clientfd, 1);
	if (ret) {
		fprintf(stderr, "register files: %s\n", strerror(-ret));
		return -1;
	}

//	ret = add_recv(&ctx, 0);
	ret = add_recvzc(&ctx, 0);
	if (ret)
		return 1;

	while (true) {
		ret = io_uring_submit_and_wait(&ctx.ring, 1);
		if (ret == -EINTR)
			continue;
		if (ret < 0) {
			fprintf(stderr, "submit and wait failed %d\n", ret);
			break;
		}

		count = io_uring_peek_batch_cqe(&ctx.ring, &cqes[0], CQES);
		for (i = 0; i < count; i++) {
			ret = process_cqe(&ctx, cqes[i], 0);
			if (ret)
				goto cleanup;
		}
		io_uring_cq_advance(&ctx.ring, count);
	}

cleanup:
	stats(&ctx, start);
	cleanup_context(&ctx);
	close(sockfd);
	return ret;
}
