# Orange Slice

Orange Slice is a research kernel and hypervisor with an end goal of creating a deterministic hypervisor. This will be developed almost entirely in my free time, and will probably move slow. However I will try to stream almost all dev for this project, such that people can ask questions and hopefully learn a thing or two about kernel and hypervisor development!

This deterministic hypervisor is going to be designed from the start for fuzzing. Having determinism in a hypervisor would allow us to never have an issue with reproducing a bug, regardless of how complex the bug is. However as a hypervisor we will benefit from the performance of hardware-accelerated virtualization.

# About Me

[Twitter]

[My Blog]

[My Youtube Channel]


## TL;DR

The end goal is a deterministic hypervisor, capable of booting Windows and Linux, with less than a 5x performance slowdown to achieve instruction-and-cycle level determinism for cycle counts and interrupt boundaries.

# Mascot

[Orange Slice Squishable]

# This is going to be developed live?

Yup. Check out [My Youtube Channel] or my [Twitter]. I announce my streams typically a few hours ahead of time, and schedule the streams on Youtube. Further for streams I think are more impactful, I try to schedule them a few days out.

I'm going to try to do much of the development live, and I'll try to help answer any questions about why certain things are being done. If this project fails, but I teach some people about OS development and get other excited about security research, then it was a success in my eyes.

I have already scheduled a stream for an intro on Wednesday: [Intro Video]

# Project Development

This will be a bootloader, kernel, and hypervisor written entirely in Rust (except for the stage0 in assembly). I already have a couple research kernels written in Rust which I will likely borrow code from.

I haven't quite determined the design of the kernel yet, but it will be multiprocessing from day one (support for SMP systems, but only single-core guests for now). I have a 256-thread Xeon Phi which I use to stress the scalability and design of the kernel. I already have many different kernel models I've experimented with before for hypervisor development, so hopefully we'll be able to make informed decisions based on past experiences.

# Building

Have `nasm`, `lld-link` (from LLVM), `python` (I use Python 3), and Rust nightly (with `i586-pc-windows-msvc` and `x86_64-pc-windows-msvc` targets installed)

Run `cargo run` in the root directory. Everything should be built :)

# Using

Copy `orange_slice.boot` and `orange_slice.kern` to a TFTPD server folder configured for PXE booting. Also set the PXE boot filename to `orange_slice.boot` in your DHCP server.

## Previous public hypervisor work

[Hypervisor for fuzzing written in C]

[Hypervisor for fuzzing written in assembly]

# What is determinism?

When running an operating system there are many different things going on. Things like cycle counts, interrupts, system times, etc, all vary during execution. On an x86 processor you'd struggle to ever get an external interrupt to come in on the same instruction boundaries, or read the same value from `rdtsc`.

This non-determinism means that you cannot simply run a previous crashing input through again and observe the same result. Things like ASLR state can be influenced by external interrupts and timers, and things like task switches also are influenced by these. Race conditions are typically extremely hard to get to reproduce, and this project aims at doing that with all the performance benefits of a hypervisor.

# What do we consider determinism?

If our goal is to develop a deterministic hypervisor, it's important that we lay down some ground rules of what we consider in scope, and not.

- The hypervisor must return the same results from all emulated devices
    - If a time is queried from a PIT/APIC/RDTSC, the same time must be returned as was in prior executions from the same snapshot
- External interrupts must be delivered on the same instruction boundaries
    - If we cannot fulfill this goal directly, then we must have a way to determine we "missed" a boundary and restore to a previous known good state which we can "try again".
- We should be able to set breakpoints on future events that we know will happen from a previous execution. This allows us to time travel debug, go back in time, and set a breakpoint on a previously observed condition.
- Probably some more... as we tailor our goals based on successes and failures

Ultimately we should be able to boot the BIOS, boot into Windows, and finally launch an application that requests the cycle count, and that cycle count should be predictable based on prior runs, and all context switches should have occurred up to that point at deterministic times.

# Why?

With my amazing team at Microsoft, we're working on a fully deterministic system level fuzzing tool (this will be open source for everyone soon, likely by late 2019, but no promises!). This is built on the existing system emulator Bochs; but with many modifications to provide APIs for fuzzing, introspection, and system-level time travel debugging. There's also some pretty nutty architecture that was designed to ensure determinism, we can't wait to share and talk about what we've done!

We made a decision early on in the project, that determinism is more important than performance. Determinism allows us to provide users with system-level time travel debugging, allowing high quality bug reports with the net effect of eliminating all "no-repro" bugs.

We have already used our new deterministic tooling to reliably reproduce obscure race conditions that historically we were unable to reproduce well enough to fix!

But, with Bochs comes a 50-100x performance slowdown. Your Windows boot now takes an hour rather than a minute, and your fuzzer performance dramatically drops. However it's worth it for the determinism. We'd rather have 10 bugs get fixed, than "know" about 15 bugs and only fix a few of them.

The ultimate goal of this project is to bring this performance overhead down from the ~50-100x we have from Bochs, to a goal of <5x. 5x may seem high for a hypervisor, but we're probably going to have to expect interrupts "early" and walk up to the correct boundary to deliver an interrupt. This may have some emulation or single stepping involved.

If the microarchitecture is nice and predictable in certain situations, then hopefully we'll be able to find a good way to get this determinism with little cost. Otherwise we might have to do things a bit crude and get around the rough edges with partial emulation.

# Timeframe

This project is not that important as it only fixes performance issues but none of the others we address with our Bochs approach, such as full-system taint tracking and the ability to fuzz hypervisors with full coverage, feedback, and determinism. It may also fail due to infeasibility, as hardware virtualization extensions are not designed with determinism in mind.

If this project succeeds, this project will likely be abandoned and a new one will be created that will be user oriented. This project is only for proving that it's possible, and exploring ways of accomplishing this goal... and of course teaching during the process!

[Orange Slice Squishable]: http://www.squishable.com/pc/comfortfood_orange_slice/Big_Animals/Comfort+Food+Orange+Slice

[My Youtube Channel]: https://www.youtube.com/user/gamozolabs
[Twitter]: https://twitter.com/gamozolabs
[Hypervisor for fuzzing written in C]: https://github.com/gamozolabs/falkervisor_grilled_cheese
[Hypervisor for fuzzing written in assembly]: https://github.com/gamozolabs/falkervisor_beta
[Intro Video]: https://youtu.be/okSUAlx_58Y
[My Blog]: https://gamozolabs.github.io/
