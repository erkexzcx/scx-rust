// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Erikas <erikmnkl@gmail.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::info;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

const SCHEDULER_NAME: &str = "scx_rustgame";

#[derive(Debug, clap::Parser)]
#[command(
    name = "scx_rustgame",
    version,
    disable_version_flag = true,
    about = "Keep one game's frame path on the CPU: sticky, preempting, SMT-isolated."
)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Process name (comm) of the game.
    #[clap(short = 'g', long, default_value = "RustClient.exe")]
    game: String,

    /// Comma-separated names of processes the game waits on: the compositor
    /// and X server on the present path, wineserver, and the audio server.
    #[clap(
        short = 'c',
        long,
        default_value = "kwin_wayland,Xwayland,kwin_x11,gnome-shell,gamescope-wl,wineserver,pipewire,pipewire-pulse"
    )]
    helpers: String,

    /// Time slice of every task outside the frame path, in microseconds.
    #[clap(short = 's', long, default_value = "2000")]
    slice_us: u64,

    /// Time slice of frame-path threads, in microseconds.
    #[clap(long, default_value = "20000")]
    slice_crit_us: u64,

    /// Maximum time non-game work waits before it is dispatched ahead of the
    /// game, in milliseconds.
    #[clap(long, default_value = "20")]
    lo_starve_ms: u64,

    /// Let job workers, game background threads and helpers use the SMT
    /// siblings of running frame-path threads. By default they stay off them
    /// while other idle CPUs exist.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    share_siblings: bool,

    /// Share of a CPU's time lost to interrupts and real-time threads above
    /// which frame-path threads move off it, in percent.
    #[clap(long, default_value = "1.5")]
    noise_pct: f64,

    /// Print statistics every this many seconds.
    #[clap(long)]
    stats: Option<f64>,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

/// Map each running process whose comm matches the game or a helper to
/// its kind.
fn scan_procs(game: &str, helpers: &[&str]) -> HashMap<u32, u32> {
    let mut found = HashMap::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return found;
    };
    for ent in dir.flatten() {
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) else {
            continue;
        };
        let comm = comm.trim_end();
        if comm == game {
            found.insert(pid, proc_kind_PROC_GAME);
        } else if helpers.contains(&comm) {
            found.insert(pid, proc_kind_PROC_HELPER);
        }
    }
    found
}

/// Per-CPU hardirq plus softirq time from /proc/stat, in nanoseconds.
fn read_irq_ns() -> Vec<u64> {
    // /proc/stat counts in USER_HZ, which is 100 on every architecture.
    const NS_PER_TICK: u64 = 10_000_000;
    let Ok(stat) = std::fs::read_to_string("/proc/stat") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in stat.lines() {
        let mut f = line.split_whitespace();
        let Some(name) = f.next() else { continue };
        let Some(id) = name
            .strip_prefix("cpu")
            .and_then(|s| s.parse::<usize>().ok())
        else {
            continue;
        };
        let v: Vec<u64> = f.filter_map(|x| x.parse().ok()).collect();
        if v.len() > 6 {
            if out.len() <= id {
                out.resize(id + 1, 0);
            }
            out[id] = (v[5] + v[6]) * NS_PER_TICK;
        }
    }
    out
}

/// Share of each CPU's time lost to interrupts and to scheduling classes above
/// sched_ext, smoothed, with hysteresis on the quiet/noisy decision.
struct Noise {
    at: Instant,
    stolen: Vec<u64>,
    irq: Vec<u64>,
    pct: Vec<f64>,
    quiet: Vec<bool>,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    procs: HashMap<u32, u32>,
    noise: Noise,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        let topo = Topology::new()?;
        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if topo.smt_enabled {
                "SMT on"
            } else {
                "SMT off"
            }
        );

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, rustgame_ops, open_opts)?;

        skel.struct_ops.rustgame_ops_mut().exit_dump_len = opts.exit_dump_len;

        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.slice_ns = opts.slice_us * 1000;
        rodata.slice_crit_ns = opts.slice_crit_us * 1000;
        rodata.lo_starve_ns = opts.lo_starve_ms * 1_000_000;
        rodata.smt_enabled = topo.smt_enabled;
        rodata.isolate_siblings = !opts.share_siblings;
        for (cpu, sib) in topo.sibling_cpus().iter().enumerate() {
            if cpu < consts_MAX_CPUS as usize {
                rodata.cpu_sibling[cpu] = *sib;
            }
        }

        skel.struct_ops.rustgame_ops_mut().flags =
            *compat::SCX_OPS_ENQ_EXITING | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED;

        let mut skel = scx_ops_load!(skel, rustgame_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, rustgame_ops)?);

        let nr_cpus = topo.all_cpus.len();
        Ok(Self {
            skel,
            struct_ops,
            procs: HashMap::new(),
            noise: Noise {
                at: Instant::now(),
                stolen: vec![0; nr_cpus],
                irq: read_irq_ns(),
                pct: vec![0.0; nr_cpus],
                quiet: vec![true; nr_cpus],
            },
        })
    }

    fn set_cpu_quiet(&mut self, cpu: usize, quiet: bool) -> Result<()> {
        let mut args = quiet_arg {
            cpu: cpu as i32,
            quiet: quiet as i32,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        self.skel.progs.set_cpu_quiet.test_run(input)?;
        Ok(())
    }

    /// Recompute each CPU's noise and move noisy CPUs out of quiet_mask.
    fn refresh_noise(&mut self, limit_pct: f64) -> Result<()> {
        let secs = self.noise.at.elapsed().as_secs_f64();
        if secs < 1.0 {
            return Ok(());
        }
        let bss = self.skel.maps.bss_data.as_ref().unwrap();
        let irq = read_irq_ns();
        let mut changed = Vec::new();
        for cpu in 0..self.noise.pct.len() {
            let stolen = bss.cpu_states[cpu].stolen_ns;
            let irq_now = irq.get(cpu).copied().unwrap_or(0);
            let lost = stolen.saturating_sub(self.noise.stolen[cpu])
                + irq_now.saturating_sub(self.noise.irq.get(cpu).copied().unwrap_or(0));
            self.noise.stolen[cpu] = stolen;
            let pct = lost as f64 / (secs * 1e7);
            self.noise.pct[cpu] = 0.5 * self.noise.pct[cpu] + 0.5 * pct;

            let quiet = if self.noise.quiet[cpu] {
                self.noise.pct[cpu] <= limit_pct
            } else {
                self.noise.pct[cpu] < limit_pct / 2.0
            };
            if quiet != self.noise.quiet[cpu] {
                self.noise.quiet[cpu] = quiet;
                changed.push((cpu, quiet));
            }
        }
        self.noise.irq = irq;
        self.noise.at = Instant::now();

        for (cpu, quiet) in changed {
            self.set_cpu_quiet(cpu, quiet)?;
            info!(
                "cpu {cpu} {} ({:.1}% lost to irq and rt)",
                if quiet { "quiet" } else { "noisy" },
                self.noise.pct[cpu]
            );
        }
        Ok(())
    }

    /// Mirror the current game and helper processes into proc_kinds.
    fn refresh_procs(&mut self, game: &str, helpers: &[&str]) -> Result<()> {
        let now = scan_procs(game, helpers);
        if now == self.procs {
            return Ok(());
        }
        let map = &self.skel.maps.proc_kinds;
        for pid in self.procs.keys().filter(|pid| !now.contains_key(pid)) {
            let _ = map.delete(&pid.to_ne_bytes());
        }
        for (pid, kind) in &now {
            map.update(&pid.to_ne_bytes(), &kind.to_ne_bytes(), MapFlags::ANY)
                .context("updating proc_kinds")?;
        }
        for (pid, kind) in &now {
            if self.procs.get(pid) != Some(kind) {
                let what = if *kind == proc_kind_PROC_GAME {
                    "game"
                } else {
                    "helper"
                };
                info!("tracking {what} pid {pid}");
            }
        }
        self.procs = now;
        let bss = self.skel.maps.bss_data.as_mut().unwrap();
        bss.class_gen += 1;
        Ok(())
    }

    fn print_stats(&self, prev: &mut [u64; 9], secs: f64) {
        let bss = self.skel.maps.bss_data.as_ref().unwrap();
        let cur = [
            bss.nr_crit_sticky,
            bss.nr_crit_idle,
            bss.nr_crit_preempt,
            bss.nr_crit_queued,
            bss.nr_job_preempt,
            bss.nr_hi_dispatch,
            bss.nr_lo_dispatch,
            bss.nr_lo_starved,
            bss.nr_crit_quiet,
        ];
        let rate = |i: usize| (cur[i] - prev[i]) as f64 / secs;
        info!(
            "crit sticky/s {:.0} idle/s {:.0} to-quiet/s {:.0} preempt/s {:.0} queued/s {:.0} | job preempt/s {:.0} | hi/s {:.0} lo/s {:.0} lo-starved/s {:.0}",
            rate(0),
            rate(1),
            rate(8),
            rate(2),
            rate(3),
            rate(4),
            rate(5),
            rate(6),
            rate(7)
        );
        *prev = cur;
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, opts: &Opts, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let helpers: Vec<&str> = opts.helpers.split(',').map(str::trim).collect();
        let mut prev = [0u64; 9];
        let mut last_stats = Instant::now();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            self.refresh_procs(&opts.game, &helpers)?;
            self.refresh_noise(opts.noise_pct)?;
            if let Some(intv) = opts.stats {
                let secs = last_stats.elapsed().as_secs_f64();
                if secs >= intv {
                    self.print_stats(&mut prev, secs);
                    last_stats = Instant::now();
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        simplelog::LevelFilter::Info,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(&opts, shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
