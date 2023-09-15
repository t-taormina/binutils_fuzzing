import glob, subprocess, random, time, threading, os, hashlib

# Run one fuzz case with the provided input which is a byte array
def fuzz(thr_id: int, inp: bytearray):
    assert isinstance(inp, bytearray)
    assert isinstance(thr_id, int)

    # Write out input to temporary file
    tmpfn = f"tmpinput{thr_id}"
    with open(tmpfn, "wb") as fd:
        fd.write(inp)

    # Run objdump to completion
    sp = subprocess.Popen(["./objdump", "-x", tmpfn],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    return_code = sp.wait()

    # Assert that the program ran successfully
    if return_code != 0:
        print(f"Exited with {return_code}")

        if return_code == -11: 
            # SIGSEGV
            dahash = hashlib.sha256(inp).hexdigest()
            open(os.path.join("crashes", f"crash_{dahash:64}"),
                              "wb").write(inp)
            #print("SIGSEGV") 


# Get a listing of all the files in the corpus.
# The corpus is the set of files which we pre-seeded the 
# fuzzer with to give it valid inputs. These are files that the 
# program sould be able to handle parsing, that we will ultimately
# mutate and splice together to try to find bugs!
corpus_filenames = glob.glob("corpus/*")

# Load the corpus files into memory
corpus = set()
for filename in corpus_filenames: 
    corpus.add(open(filename, "rb").read())

# Convert the corpus back to a list as we're done with the set for deduping 
# inputs which were not unique
corpus = list(map(bytearray, corpus))

# Get fuzzer start time
start = time.time()

# Total number of fuzz cases
cases = 0

def worker(thr_id):
    global start, corpus, cases

    while True: 
        # Create a copy of an existing input from the corpus
        inp = bytearray(random.choice(corpus))

        for _ in range(random.randint(1, 8)):
            inp[random.randint(0, len(inp) - 1)] = random.randint(0, 255)

        # Pick random input from corpus
        fuzz(thr_id, inp)

        # Update the number of fuzz cases
        cases += 1
        
        # Determine amount of seconds we have been fuzzing for
        elapsed = time.time() - start

        # Determine fuzz cases per second
        fcps =  float(cases) / elapsed

        if thr_id == 0:
            print(f"[{elapsed:10.4}] cases {cases:10} |  fcps {fcps:10.4f}")

for thr_id in range(25):
    threading.Thread(target=worker, args=[thr_id]).start()

while threading.active_count() > 0: 
    time.sleep(0.1)

