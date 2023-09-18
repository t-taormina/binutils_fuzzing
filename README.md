# objdump fuzzing
- This repository contains code for fuzzing the objdump feature of binutils. For this, I have built a binutils executable from 2003 since this version will likely have a lot more bugs and it will be significantly less likely to find a relevant bug. This is strictly for my own educational purposes as it is the first fuzzer I have worked on. I am using gamozolabs as a resource. He set out to write this snap shot fuzzer as a proof of concept that snap shot fuzzers offer multiple improvements over traditional fuzzers. I am following along with some of the research that he has done in the past as a learning exercise. Currently the fuzzers are written in Python and Rust.

### Currently working on...
- Currently working on a RISC-V emulator that will be responsible for doing the fuzzing. Instead of spinning up processes, Emulators will be spun up. Hopefully this demonstrates some of the capabilities and benefits of snapshot fuzzing i.e. scalability, coverage, feedback, and instrumentation. 

# THIS README IS A WORK IN PROGRESS
