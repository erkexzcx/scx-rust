# scx_rustgame

A sched_ext scheduler that does one thing: keep one game's frame path on the
CPU. The default target is Rust (Facepunch), running as `RustClient.exe`
under Proton, but any Unity + DXVK game works with `--game <comm>`.

## Why

Under EEVDF, Rust's main thread migrates about three times per frame, and
its render thread (`UnityGfxDeviceW`) and DXVK's `dxvk-cs` migrate several
times more. The main thread is also preempted hundreds of times per second
by the game's own job workers and shader compilers, which share its nice
level. When the machine has other work to do, the frame path waits in the
same queues as everything else, along with the amdgpu GPU scheduler workers
and `wineserver`, which DXVK and Wine depend on.

## How

User space lists the game's tgid and those of its helpers (compositor, X
server, `wineserver`, PipeWire) in a BPF map. BPF sorts every thread into a
class, by its comm inside those processes:

| class | threads | treatment |
| --- | --- | --- |
| frame path | main thread, `UnityGfx*`, `dxvk-cs`, `dxvk-submit`, `dxvk-queue`, `dxvk-frame`, `WSI swapchain*` | back on its previous CPU, preempting anything lower; 20 ms slices |
| helper | kernel threads, helper processes | preempts job workers and below |
| job | `Job.Worker*` | prefers its previous CPU, then idle cores; preempts game background threads and non-game work |
| game background | every other game thread | ahead of non-game work |
| normal | everything else | weighted vtime |

Placement rules for the frame path:

- While a frame-path thread runs, its SMT sibling is kept free of every
  lower class as long as other idle CPUs exist. A CPU-bound Unity main
  thread runs measurably faster with an idle sibling.
- Two frame-path threads never settle on the siblings of one core. Because
  they are sticky, they would otherwise share it for the whole session.
- Frame-path threads leave CPUs that lose more than `--noise-pct` of their
  time to interrupts and real-time threads (the amdgpu or NIC interrupt CPU,
  a CPU where kwin or PipeWire keep waking). `ops.cpu_release()` and
  `ops.cpu_acquire()` measure the real-time share, and `/proc/stat` gives
  the interrupt share.

Non-game work is dispatched ahead of the game whenever none of it has run
for `--lo-starve-ms`, so a busy game cannot starve the desktop.

## Results

Ryzen 7 9800X3D, Radeon RX 9070 XT, standing still on a populated server.
MangoHud per-frame logs, 20 s captures interleaved with EEVDF, after one
discarded warm-up capture.

720p windowed, vsync off: the Unity main thread is the bottleneck.

| load | scheduler | runs | avg FPS | 1% low | 0.1% low |
| --- | --- | --- | --- | --- | --- |
| idle desktop | EEVDF | 5 | 281.1 | 217.8 | 196.3 |
| idle desktop | scx_rustgame | 5 | 287.9 | 234.3 | 197.7 |
| 16 nice-0 CPU hogs | EEVDF | 3 | 61.6 | 32.8 | 28.2 |
| 16 nice-0 CPU hogs | scx_rustgame | 2 | 166.7 | 124.5 | 111.6 |

At 3840x2160 the GPU is at 99.7% load and at its power cap, so the average
cannot move. An earlier build, without the placement rules above, already
raised the 1% low from 126.7 to 134.1 and the 0.1% low from 104.3 to 124.5
there.

## Usage

```sh
sudo scx_rustgame                      # Rust
sudo scx_rustgame --game Game.exe      # another Unity + DXVK title
sudo scx_rustgame --stats 5            # print decision counters
```

The scheduler can run all the time. With no game running, it is a plain
vtime scheduler in which kernel threads and the helper processes go first.
