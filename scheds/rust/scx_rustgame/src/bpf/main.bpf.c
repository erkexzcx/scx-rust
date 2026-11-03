/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_rustgame: keep one game's frame path on the CPU.
 *
 * Under EEVDF, Rust (Unity, IL2CPP, DXVK under Proton) migrates its main
 * thread about three times per frame and its render and DXVK submission
 * threads several times more, and the main thread is preempted by its own
 * job workers and shader compilers, which share its nice level. This
 * scheduler sorts the game's threads into classes and enforces three rules:
 *
 * - Frame-path threads (CLS_CRIT) are sticky. They go back to the CPU they
 *   last ran on and preempt anything of a lower class there.
 * - While a frame-path thread runs, its CPU and that CPU's SMT sibling are
 *   kept free of non-game tasks.
 * - Higher classes are dispatched first. Non-game work is ordered by weighted
 *   vtime and is guaranteed a dispatch within lo_starve_ns.
 *
 * User space finds the game and helper processes and lists their tgids
 * in proc_kinds. Threads are classified by their comm within those tgids.
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* Shared DSQs: game and helper work, and everything else. */
#define HI_DSQ		0
#define LO_DSQ		1

const volatile u64 slice_ns = 2ULL * NSEC_PER_MSEC;
const volatile u64 slice_crit_ns = 20ULL * NSEC_PER_MSEC;
const volatile u64 slice_lag_ns = 20ULL * NSEC_PER_MSEC;
const volatile u64 lo_starve_ns = 20ULL * NSEC_PER_MSEC;
const volatile bool smt_enabled = true;
const volatile s32 cpu_sibling[MAX_CPUS];

/*
 * Keep game work below the frame path off frame-path SMT siblings while
 * other idle CPUs exist. A CPU-bound main thread runs measurably faster with
 * its sibling idle.
 */
const volatile bool isolate_siblings = true;

/*
 * Bumped by user space whenever proc_kinds changes, so cached task classes
 * are recomputed.
 */
volatile u64 class_gen;

volatile u64 nr_crit_sticky, nr_crit_preempt, nr_crit_idle, nr_crit_queued;
volatile u64 nr_job_preempt, nr_hi_dispatch, nr_lo_dispatch, nr_lo_starved;
volatile u64 nr_crit_quiet;

static u64 nr_cpu_ids;
static u64 vtime_now;
static u64 lo_last_dispatch;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, u32);
	__type(value, u32);
} proc_kinds SEC(".maps");

/*
 * Class of the task each CPU is running (CLS_NONE when idle) and when that
 * task started.
 */
struct cpu_state {
	u32 cls;
	u64 last_run_at;
	u64 released_at;	/* when a higher class took the CPU */
	u64 stolen_ns;		/* total time higher classes held it */
};

struct cpu_state cpu_states[MAX_CPUS];

static struct cpu_state *cpu_state(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS)
		return NULL;
	/* MAX_CPUS is a power of two: the mask keeps the verifier convinced. */
	return &cpu_states[cpu & (MAX_CPUS - 1)];
}

static u32 cpu_cls(s32 cpu)
{
	struct cpu_state *cs = cpu_state(cpu);

	return cs ? cs->cls : CLS_MAX;
}

/*
 * CPUs a non-game task may take while idle: all CPUs minus those running a
 * frame-path thread and their SMT siblings.
 */
private(RUSTGAME) struct bpf_cpumask __kptr *normal_mask;

/*
 * CPUs that lose little time to interrupts and real-time threads, as measured
 * by user space. Frame-path threads are sticky, so one that lands on a noisy
 * CPU would otherwise keep paying for it.
 */
private(RUSTGAME) struct bpf_cpumask __kptr *quiet_mask;

struct task_ctx {
	u64 class_gen;
	u64 class_at;
	u32 cls;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

static struct task_ctx *lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
}

static s32 sibling(s32 cpu)
{
	if (!smt_enabled || cpu < 0 || cpu >= MAX_CPUS)
		return -1;
	return cpu_sibling[cpu & (MAX_CPUS - 1)];
}

static bool cpu_allowed(const struct task_struct *p, s32 cpu)
{
	if (cpu < 0 || cpu >= nr_cpu_ids)
		return false;
	if (p->nr_cpus_allowed == 1 || is_migration_disabled(p))
		return cpu == scx_bpf_task_cpu(p);
	return bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
}

/*
 * Classify a thread of a game process by name. Wine names threads after
 * SetThreadDescription(), which can happen after the thread starts, so the
 * result is cached only briefly.
 */
static u32 classify_game_thread(const struct task_struct *p)
{
	char comm[16];

	if (p->pid == p->tgid)
		return CLS_CRIT;

	if (bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm) < 0)
		return CLS_GAME_BG;

	if (!bpf_strncmp(comm, 8, "UnityGfx") ||
	    !bpf_strncmp(comm, 8, "dxvk-cs") ||
	    !bpf_strncmp(comm, 12, "dxvk-submit") ||
	    !bpf_strncmp(comm, 11, "dxvk-queue") ||
	    !bpf_strncmp(comm, 11, "dxvk-frame") ||
	    !bpf_strncmp(comm, 13, "WSI swapchain"))
		return CLS_CRIT;

	if (!bpf_strncmp(comm, 10, "Job.Worker"))
		return CLS_JOB;

	return CLS_GAME_BG;
}

static u32 task_class(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 now = bpf_ktime_get_ns();
	u32 tgid = p->tgid, *kind;
	u32 cls = CLS_NORMAL;

	if (tctx->cls && tctx->class_gen == class_gen &&
	    now - tctx->class_at < 250 * NSEC_PER_MSEC)
		return tctx->cls;

	/*
	 * Kernel threads include the GPU scheduler workers that push DXVK's
	 * submissions to the ring. Workqueue names are not in comm, so they
	 * cannot be singled out, and kernel threads are short-running anyway.
	 */
	if (p->flags & PF_KTHREAD) {
		cls = CLS_HELPER;
		goto out;
	}

	kind = bpf_map_lookup_elem(&proc_kinds, &tgid);
	if (kind) {
		if (*kind == PROC_HELPER)
			cls = CLS_HELPER;
		else
			cls = classify_game_thread(p);
	}
out:
	tctx->cls = cls;
	tctx->class_gen = class_gen;
	tctx->class_at = now;

	return cls;
}

static u64 class_slice(u32 cls)
{
	return cls == CLS_CRIT ? slice_crit_ns : slice_ns;
}

/*
 * Order within HI_DSQ: FIFO by enqueue time, with higher classes jumping
 * ahead.
 */
static u64 hi_key(u32 cls)
{
	u64 now = bpf_ktime_get_ns();

	switch (cls) {
	case CLS_CRIT:
		return now - 4 * NSEC_PER_MSEC;
	case CLS_HELPER:
		return now - 2 * NSEC_PER_MSEC;
	case CLS_GAME_BG:
		return now + 2 * NSEC_PER_MSEC;
	default:
		return now;
	}
}

static u64 lo_vtime(const struct task_struct *p)
{
	u64 vtime = p->scx.dsq_vtime;
	u64 floor = vtime_now - scale_by_task_weight_inverse(p, slice_lag_ns);

	if (time_before(vtime, floor))
		vtime = floor;
	return vtime;
}

/*
 * Find an idle CPU for @p, preferring @prev when it is idle and then fully
 * idle cores. Non-game tasks are kept to normal_mask.
 */
static s32 pick_idle(struct task_struct *p, s32 prev, u64 wake_flags, u32 cls)
{
	const struct cpumask *mask = cast_mask(normal_mask);
	s32 cpu;

	if (cls >= CLS_JOB) {
		if (isolate_siblings && cls != CLS_CRIT && mask) {
			if (cpu_allowed(p, prev) && bpf_cpumask_test_cpu(prev, mask) &&
			    scx_bpf_test_and_clear_cpu_idle(prev))
				return prev;
			cpu = scx_bpf_select_cpu_and(p, prev, wake_flags, mask,
						     SCX_PICK_IDLE_CORE);
			if (cpu >= 0)
				return cpu;
			cpu = scx_bpf_select_cpu_and(p, prev, wake_flags, mask, 0);
			if (cpu >= 0)
				return cpu;
		}
		if (cpu_allowed(p, prev) && scx_bpf_test_and_clear_cpu_idle(prev))
			return prev;
		cpu = scx_bpf_select_cpu_and(p, prev, wake_flags, p->cpus_ptr,
					     SCX_PICK_IDLE_CORE);
		if (cpu >= 0)
			return cpu;
		return scx_bpf_select_cpu_and(p, prev, wake_flags, p->cpus_ptr, 0);
	}

	if (!mask)
		return -EBUSY;
	return scx_bpf_select_cpu_and(p, prev, wake_flags, mask, 0);
}

/*
 * Find a CPU usable by @p that is running something of a lower class than
 * @cls, preferring @prev, then the lowest class found.
 *
 * CLS_NONE means idle, or between a task being dispatched to the CPU and it
 * starting to run. Idle CPUs are pick_idle()'s job, and preempting a CPU in
 * that window would jump ahead of whatever was just dispatched there, so only
 * the frame path, which outranks anything that could be in flight, may take
 * such a CPU, and only its own previous one.
 */
static s32 find_preempt_cpu(const struct task_struct *p, s32 prev, u32 cls)
{
	u32 best_cls = cls;
	s32 best = -1;
	u64 i;

	if (cpu_allowed(p, prev)) {
		u32 c = cpu_cls(prev);

		if (c < cls && (c != CLS_NONE || cls == CLS_CRIT))
			return prev;
	}

	bpf_for(i, 0, nr_cpu_ids) {
		u32 c = cpu_cls(i);

		if (c != CLS_NONE && c < best_cls && cpu_allowed(p, i)) {
			best = i;
			best_cls = c;
			if (c <= CLS_NORMAL)
				break;
		}
	}
	return best;
}

s32 BPF_STRUCT_OPS(rustgame_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	u32 cls;
	s32 cpu;

	if (!tctx)
		return prev_cpu;
	cls = task_class(p, tctx);

	/* Leave a noisy CPU for a fully idle quiet core. */
	if (cls == CLS_CRIT) {
		const struct cpumask *quiet = cast_mask(quiet_mask);

		if (quiet && !bpf_cpumask_test_cpu(prev_cpu, quiet)) {
			cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, quiet,
						     SCX_PICK_IDLE_CORE);
			if (cpu >= 0) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_crit_ns, 0);
				__sync_fetch_and_add(&nr_crit_quiet, 1);
				return cpu;
			}
		}
	}

	/*
	 * Two frame-path threads on SMT siblings of one core would stay there
	 * for good, since both are sticky: move to a fully idle core if there
	 * is one.
	 */
	if (cls == CLS_CRIT && cpu_cls(sibling(prev_cpu)) == CLS_CRIT) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr,
					     SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_crit_ns, 0);
			__sync_fetch_and_add(&nr_crit_idle, 1);
			return cpu;
		}
	}

	/*
	 * A frame-path thread whose previous CPU is busy with lower-class work
	 * stays there and preempts it from ops.enqueue(). Keeping its L1/L2
	 * warm is worth more than an idle CPU elsewhere.
	 */
	if (cls == CLS_CRIT && cpu_allowed(p, prev_cpu)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_crit_ns, 0);
			__sync_fetch_and_add(&nr_crit_sticky, 1);
			return prev_cpu;
		}
		if (cpu_cls(prev_cpu) < CLS_CRIT)
			return prev_cpu;
	}

	cpu = pick_idle(p, prev_cpu, wake_flags, cls);
	if (cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, class_slice(cls), 0);
		if (cls == CLS_CRIT)
			__sync_fetch_and_add(cpu == prev_cpu ? &nr_crit_sticky :
							       &nr_crit_idle, 1);
		return cpu;
	}
	return prev_cpu;
}

static void kick_idle_for(struct task_struct *p, u32 cls)
{
	const struct cpumask *mask = cast_mask(normal_mask);
	s32 cpu;

	/* Separate calls: the verifier rejects one call site fed two pointer types. */
	if (cls >= CLS_JOB)
		cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	else if (mask)
		cpu = scx_bpf_pick_idle_cpu(mask, 0);
	else
		return;
	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(rustgame_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	s32 prev = scx_bpf_task_cpu(p), cpu;
	u32 cls;

	if (!tctx) {
		scx_bpf_dsq_insert_vtime(p, LO_DSQ, slice_ns, lo_vtime(p), enq_flags);
		return;
	}
	cls = task_class(p, tctx);

	/*
	 * ops.select_cpu() was skipped (or the task was preempted): look for
	 * an idle CPU here.
	 */
	if (!__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p)) {
		cpu = pick_idle(p, prev, 0, cls);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					   class_slice(cls), enq_flags);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}

	if (cls >= CLS_GAME_BG) {
		/*
		 * Take a CPU from lower-class work. Nothing below the frame path
		 * can displace it, and non-game tasks give way to all game
		 * threads and helpers.
		 */
		cpu = find_preempt_cpu(p, prev, cls);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, class_slice(cls),
					   enq_flags | SCX_ENQ_PREEMPT);
			if (cls == CLS_CRIT)
				__sync_fetch_and_add(&nr_crit_preempt, 1);
			else
				__sync_fetch_and_add(&nr_job_preempt, 1);
			return;
		}
		if (cls == CLS_CRIT)
			__sync_fetch_and_add(&nr_crit_queued, 1);
		scx_bpf_dsq_insert_vtime(p, HI_DSQ, class_slice(cls), hi_key(cls),
					 enq_flags);
		kick_idle_for(p, cls);
		return;
	}

	scx_bpf_dsq_insert_vtime(p, LO_DSQ, slice_ns, lo_vtime(p), enq_flags);
	kick_idle_for(p, cls);
}

void BPF_STRUCT_OPS(rustgame_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 now = bpf_ktime_get_ns();

	/*
	 * Give non-game work a turn when none of it has been dispatched for
	 * lo_starve_ns, so a busy game cannot starve the rest of the system.
	 * A per-CPU version of this guard measured worse 0.1% lows.
	 */
	if (time_after(now, lo_last_dispatch + lo_starve_ns) &&
	    scx_bpf_dsq_move_to_local(LO_DSQ, 0)) {
		lo_last_dispatch = now;
		__sync_fetch_and_add(&nr_lo_starved, 1);
		return;
	}

	if (scx_bpf_dsq_move_to_local(HI_DSQ, 0)) {
		__sync_fetch_and_add(&nr_hi_dispatch, 1);
		return;
	}

	if (scx_bpf_dsq_move_to_local(LO_DSQ, 0)) {
		lo_last_dispatch = now;
		__sync_fetch_and_add(&nr_lo_dispatch, 1);
		return;
	}

	/* Nothing else wants this CPU: let @prev keep running. */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
		struct task_ctx *tctx = lookup_task_ctx(prev);

		scx_bpf_task_set_slice(prev, tctx ? class_slice(tctx->cls) : slice_ns);
	}
}

static void normal_mask_update(s32 cpu, bool reserve)
{
	struct bpf_cpumask *mask = normal_mask;
	s32 sib = sibling(cpu);

	if (!mask || cpu < 0 || cpu >= nr_cpu_ids)
		return;

	if (reserve) {
		bpf_cpumask_clear_cpu(cpu, mask);
		if (sib >= 0 && sib < nr_cpu_ids)
			bpf_cpumask_clear_cpu(sib, mask);
		return;
	}

	/* Release the core unless its sibling still runs the frame path. */
	if (sib >= 0 && sib < nr_cpu_ids && cpu_cls(sib) == CLS_CRIT)
		return;
	bpf_cpumask_set_cpu(cpu, mask);
	if (sib >= 0 && sib < nr_cpu_ids)
		bpf_cpumask_set_cpu(sib, mask);
}

void BPF_STRUCT_OPS(rustgame_running, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx = lookup_task_ctx(p);
	struct cpu_state *cs = cpu_state(cpu);
	u32 cls = tctx ? tctx->cls : CLS_NORMAL;

	if (!cs)
		return;
	cs->cls = cls ? cls : CLS_NORMAL;
	cs->last_run_at = bpf_ktime_get_ns();

	if (cls == CLS_CRIT)
		normal_mask_update(cpu, true);

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(rustgame_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);
	struct cpu_state *cs = cpu_state(cpu);
	u32 cls;

	if (!cs)
		return;
	cls = cs->cls;
	cs->cls = CLS_NONE;

	if (cls == CLS_CRIT)
		normal_mask_update(cpu, false);

	scx_bpf_task_set_dsq_vtime(p, p->scx.dsq_vtime +
		scale_by_task_weight_inverse(p, bpf_ktime_get_ns() - cs->last_run_at));
}

void BPF_STRUCT_OPS(rustgame_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	struct cpu_state *cs = cpu_state(cpu);

	if (cs)
		cs->released_at = bpf_ktime_get_ns();
}

void BPF_STRUCT_OPS(rustgame_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	struct cpu_state *cs = cpu_state(cpu);

	if (cs && cs->released_at) {
		cs->stolen_ns += bpf_ktime_get_ns() - cs->released_at;
		cs->released_at = 0;
	}
}

SEC("syscall")
int set_cpu_quiet(struct quiet_arg *input)
{
	struct bpf_cpumask *mask;

	bpf_rcu_read_lock();
	mask = quiet_mask;
	if (mask && input->cpu >= 0 && input->cpu < nr_cpu_ids) {
		if (input->quiet)
			bpf_cpumask_set_cpu(input->cpu, mask);
		else
			bpf_cpumask_clear_cpu(input->cpu, mask);
	}
	bpf_rcu_read_unlock();
	return 0;
}

void BPF_STRUCT_OPS(rustgame_enable, struct task_struct *p)
{
	scx_bpf_task_set_dsq_vtime(p, vtime_now);
}

s32 BPF_STRUCT_OPS(rustgame_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	if (!bpf_task_storage_get(&task_ctx_stor, p, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE))
		return -ENOMEM;
	return 0;
}

void BPF_STRUCT_OPS(rustgame_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rustgame_init)
{
	struct bpf_cpumask *mask;
	s32 cpu, err;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	err = scx_bpf_create_dsq(HI_DSQ, -1);
	if (err)
		return err;
	err = scx_bpf_create_dsq(LO_DSQ, -1);
	if (err)
		return err;

	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;
	bpf_for(cpu, 0, nr_cpu_ids)
		bpf_cpumask_set_cpu(cpu, mask);
	mask = bpf_kptr_xchg(&normal_mask, mask);
	if (mask)
		bpf_cpumask_release(mask);

	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;
	bpf_for(cpu, 0, nr_cpu_ids)
		bpf_cpumask_set_cpu(cpu, mask);
	mask = bpf_kptr_xchg(&quiet_mask, mask);
	if (mask)
		bpf_cpumask_release(mask);

	return 0;
}

SCX_OPS_DEFINE(rustgame_ops,
	       .select_cpu		= (void *)rustgame_select_cpu,
	       .enqueue			= (void *)rustgame_enqueue,
	       .dispatch		= (void *)rustgame_dispatch,
	       .running			= (void *)rustgame_running,
	       .stopping		= (void *)rustgame_stopping,
	       .cpu_acquire		= (void *)rustgame_cpu_acquire,
	       .cpu_release		= (void *)rustgame_cpu_release,
	       .enable			= (void *)rustgame_enable,
	       .init_task		= (void *)rustgame_init_task,
	       .init			= (void *)rustgame_init,
	       .exit			= (void *)rustgame_exit,
	       .timeout_ms		= 5000,
	       .name			= "rustgame");
