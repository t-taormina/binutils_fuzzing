import glob, subprocess, random, time, threading

# Run one fuzz case with the provided input which is a byte array
def fuzz(thr_id, input):
    assert isinstance(input, bytearray)
    assert isinstance(thr_id, int)

    # Write out input to temporary file
    tmpfn = f"tmpinput{thr_id}"
    with open(tmpfn, "wb") as fd:
        fd.write(input)

    # Run objdump to completion
    sp = subprocess.Popen(["./objdump", "-x", tmpfn],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    return_code = sp.wait()

    # Assert that the program ran successfully
    if return_code != 0:
        print(f"Exited with {return_code}")


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
            inp[random.randint(0, len(inp))] = random.randint(0, 255)

        # Pick random input from corpus
        fuzz(thr_id, random.choice(corpus))

        # Update the number of fuzz cases
        cases += 1
        
        # Determine amount of seconds we have been fuzzing for
        elapsed = time.time() - start

        # Determine fuzz cases per second
        fcps =  float(cases) / elapsed

        print(f"[{elapsed:10.4}] cases {cases:10} |  fcps {fcps:10.4f}")

for thr_id in range(25):
    threading.Thread(target=worker, args=[thr_id]).start()

while threading.active_count() > 0: 
    time.sleep(0.1)

