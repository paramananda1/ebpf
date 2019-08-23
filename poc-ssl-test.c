#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */
struct probe_SSL_data_t {
	u64 timestamp_ns;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char v0[464];
    u32 len;
};

BPF_PERF_OUTPUT(perf_SSL_write);

int probe_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    struct probe_SSL_data_t __data = {0};
    __data.timestamp_ns = bpf_ktime_get_ns();
    __data.pid = bpf_get_current_pid_tgid();
    __data.len = num;
    
	bpf_get_current_comm(&__data.comm, sizeof(__data.comm));
    
	if ( buf != 0) {
    	bpf_probe_read(&__data.v0, sizeof(__data.v0), buf);
    }
    
	perf_SSL_write.perf_submit(ctx, &__data, sizeof(__data));
    return 0;
}

BPF_PERF_OUTPUT(perf_SSL_read_enter);
BPF_HASH(bufs, u32, u64);

int probe_SSL_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
	u32 pid = bpf_get_current_pid_tgid();
    bufs.update(&pid, (u64*)&buf);
    return 0;
}


BPF_PERF_OUTPUT(perf_SSL_read_exit);
int probe_SSL_read_exit(struct pt_regs *ctx, void *ssl, void *buf, int num) {
	u32 pid = bpf_get_current_pid_tgid();
    struct probe_SSL_data_t **bufp = (struct probe_SSL_data_t **)bufs.lookup(&pid);
    if (bufp == 0) {
    	return 0;
	}
    struct probe_SSL_data_t __data = {0};
    	__data.timestamp_ns = bpf_ktime_get_ns();
        __data.pid = pid;
        __data.len = PT_REGS_RC(ctx);
        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));
        if (bufp != 0) {
        	bpf_probe_read(&__data.v0, sizeof(__data.v0), (*bufp)->v0);
        }
        bufs.delete(&pid);
        perf_SSL_read_exit.perf_submit(ctx, &__data, sizeof(__data));
		
	return 0;
}
