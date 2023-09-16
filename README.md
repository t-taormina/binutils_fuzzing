# objdump fuzzing
- This repository contains code for fuzzing the objdump feature of binutils. For this, I have built a binutils from 2003 since this version will likely have a lot more bugs and it will be significantly less likely to find a relevant bug. This is strictly for my own educational purposes as it is the first fuzzer I have worked on. I am using gamozolabs as a resource. He has fantastic content on hacking and low-level programming on all major content platforms(youtube/twitch are what I am using). Currently the fuzzer is written in Python and Rust.

### Future Plan
- Since a fuzzer needs to throw LOTS of stuff at a target, it makes sense to focus on performance of the program. Moving from Python to Rust has brought on some expected perf improvements. The code has been written to support multi-threading so that has helped as well. Even with these enhancements, the program does not scale remotely close to linearly when adding more cores. The main reason behind this is how slow the kernel is when spinning up processes, copying memory, writing pages, deleting pages, etc. If someone wanted to see the numbers behind this I could get some supporting screen shots, just let me know. 
- All the above in mind, I am writing a RISC-V emulator that will be responsible for doing the fuzzing. Instead of spinning up processes, Emulators will be spun up. This will allow numerous benefits which I will carefully detail in the coming days. I need to research things a bit more before posting them here.


# WORK IN PROGRESS
