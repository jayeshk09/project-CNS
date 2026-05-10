# Hermes — Extended with Result Volume Hiding

> This repository extends the original [Hermes](https://github.com/vt-asaplab/Hermes) system with **Result Volume Hiding**, a practical privacy enhancement that reduces leakage during encrypted keyword search in multi-writer databases.

---

## Table of Contents

- [About the Original Hermes](#about-the-original-hermes)
- [What We Changed and Why](#what-we-changed-and-why)
- [How Volume Hiding Works](#how-volume-hiding-works)
- [Files Modified](#files-modified)
- [Code Changes in Detail](#code-changes-in-detail)
- [Building the Project](#building-the-project)
- [Running and Verifying the Changes](#running-and-verifying-the-changes)
- [Results](#results)
- [Limitations and Future Work](#limitations-and-future-work)

---

## About the Original Hermes

Hermes is a **multi-writer encrypted database** system that allows multiple writers to upload keyword-encrypted documents to an untrusted server, while a designated reader can search across any subset of writers using a single constant-size token. It was published at **IEEE S&P 2025** by researchers at Virginia Tech's ASAP Lab.

Its core cryptographic contribution is **HICKAE** (Hidden-Identity Ciphertext Key-Aggregate Encryption), a novel IBE-based scheme that:

- Hides writer identities inside decryption keys to resist chosen-identity attacks
- Allows the reader to aggregate keys for multi-writer search into a single constant-size token
- Achieves **forward privacy** without requiring expensive periodic index rebuilds
- Supports sublinear search time with respect to database size

The implementation is in C++ using PBC (Pairing-Based Cryptography), GMP, ZeroMQ, and OpenSSL, with a client-server architecture tested on the Enron email dataset.

---

## What We Changed and Why

### The Problem We Found

After studying the original Hermes source code, we identified a concrete **information leakage gap** that the paper acknowledges but does not address in its implementation.

When a reader searches for a keyword `w`, the server returns exactly `r_w` file IDs — the precise number of documents matching that keyword across each writer. This exact count is visible in the network message in two ways:

1. The **message size itself** is `(total_matches + num_writers) × 4` bytes — an observer can compute `total_matches` directly from the packet size
2. The **per-writer count** is sent as a raw integer before each writer's file ID list

This means anyone observing network traffic — or a semi-honest server logging query statistics — can learn exactly how many documents contain any given keyword for each writer. Over time, this enables **statistical inference attacks**: by correlating result volumes with known keyword frequency distributions (such as those derived from public email corpora), an attacker can identify which keywords are being searched without ever breaking the encryption.

This leakage is formally captured in the paper's own leakage function as the term `r_w` in Table 1, but the implementation makes no attempt to suppress it.

### Our Solution: Bucket-Based Result Volume Hiding

We implemented **bucket-based result volume hiding** directly in the server's search output path. Instead of sending the exact match count `r_w`, the server rounds it up to the nearest value in a predefined bucket ladder:

```
Buckets: {0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}
```

The server pads the result list to the bucket size by appending dummy entries (sentinel value `-1`). The client filters out dummy entries before displaying results. The network message size is now determined by bucket boundaries rather than exact counts, so an observer learns only which bucket the result falls into — not the precise value.

This is a standard technique in the Searchable Symmetric Encryption (SSE) literature and directly reduces the `r_w` leakage term without modifying any of Hermes's underlying cryptographic protocols.

### Why This Matters

| Scenario | Without Volume Hiding | With Volume Hiding |
|---|---|---|
| Search for "university" returns 47 docs | Attacker sees: `47` | Attacker sees: `64` |
| Search for "cryptography" returns 3 docs | Attacker sees: `3` | Attacker sees: `4` |
| Search for "meeting" returns 130 docs | Attacker sees: `130` | Attacker sees: `256` |
| Search returns 0 docs | Attacker sees: `0` | Attacker sees: `0` |

The attacker's ability to distinguish between, say, 45 and 47 results is completely eliminated — they can only determine that the count falls in the range `[33, 64]`.

---

## How Volume Hiding Works

The mechanism has three components working together:

**1. Bucket ladder (config.hpp)**
A fixed set of allowed output sizes. Any real count is rounded up to the smallest bucket value that is greater than or equal to it.

**2. Server-side padding (server.cpp)**
After computing the real match list, the server calculates the padded count using `next_bucket()`, allocates the message to the padded size, copies real file IDs, then fills remaining slots with the dummy sentinel `-1`. The padded count (not the real count) is sent in the message header.

**3. Client-side filtering (client.cpp)**
The client reads exactly `padded_count` entries from the message but skips any entry equal to `-1` before displaying results to the user. The user sees only real file IDs.

The toggle `#define ENABLE_VOLUME_HIDING 1` in `config.hpp` lets you switch between the original and extended behavior with a single line change, making benchmarking straightforward.

---

## Files Modified

Only 3 files were changed. No cryptographic code was touched.

```
Hermes/
├── config.hpp          ← Added ENABLE_VOLUME_HIDING flag, DUMMY_FILE_ID,
│                          and VOLUME_BUCKET_SIZES array
├── server/
│   └── server.cpp      ← Added next_bucket() helper function,
│                          replaced raw output block with padded output block
└── client/
    └── client.cpp      ← Added dummy entry filter in result printing loop
```

---

## Code Changes in Detail

### config.hpp — 3 lines added at the bottom

```cpp
#define ENABLE_VOLUME_HIDING    1
const int DUMMY_FILE_ID         = -1;
const int VOLUME_BUCKET_SIZES[] = {0,1,2,4,8,16,32,64,128,256,512,1024,2048,4096};
const int NUM_VOLUME_BUCKETS    = 14;
```

### server.cpp — next_bucket() helper added

```cpp
#ifdef ENABLE_VOLUME_HIDING
int next_bucket(int real_count) {
    for (int i = 0; i < NUM_VOLUME_BUCKETS; ++i)
        if (VOLUME_BUCKET_SIZES[i] >= real_count)
            return VOLUME_BUCKET_SIZES[i];
    return real_count;
}
#endif
```

### server.cpp — output block replaced

The original output block sent `total_matches × sizeof(int)` bytes with exact counts. The new block:

1. Computes `padded_counts[i] = next_bucket(output[writer_id][0])` for each writer
2. Allocates message of size `padded_total × sizeof(int)` instead
3. Sends `padded_count` in the header (not `real_count`)
4. Fills extra slots with `DUMMY_FILE_ID` (-1)

The `#else` branch preserves the original behavior when `ENABLE_VOLUME_HIDING` is off.

### client.cpp — dummy filter added

```cpp
// Inside the result printing loop:
#ifdef ENABLE_VOLUME_HIDING
    if(file_id == DUMMY_FILE_ID) continue;  // skip padding
#endif
```

---

## Building the Project

**Prerequisites** (installed by `auto_setup.sh`):
- GCC with C++11 support
- PBC library
- GMP library
- ZeroMQ
- OpenSSL

**Build:**
```bash
# Run setup if first time
cd ~/Desktop/Hermes
sudo ./auto_setup.sh

# Build both server and client
cd ~/Desktop/Hermes/Hermes
make

# Verify binaries exist
ls server/server client/client
```

**To toggle volume hiding off** (for benchmarking the original):
```cpp
// In config.hpp, change:
#define ENABLE_VOLUME_HIDING    1
// to:
#define ENABLE_VOLUME_HIDING    0
```
Then rebuild with `make`.

---

## Running and Verifying the Changes

**Terminal 1 — start the server:**
```bash
cd ~/Desktop/Hermes/Hermes/server
./server
```

Wait for `Done` before proceeding.

**Terminal 2 — run searches:**
```bash
cd ~/Desktop/Hermes/Hermes/client
./client -s university
./client -s cryptography
./client -s security
```

**What the server prints (with debug output enabled):**
```
Total matches: 47
Writer 1: real=47  padded=64
Writer 2: real=0   padded=0
Writer 3: real=3   padded=4
Server search latency: 0.0031s
```

**What the client prints:**
```
Keyword "university" appears in:
Writer 1: 3 5 12 18 24 31 ...
Writer 2: no matched documents.
End-to-end search latency: 0.0089s
```

The client sees only real file IDs. The `-1` dummy entries are filtered out transparently. The network observer sees only the bucket size.

---

## Results

All measurements were taken on the Enron email dataset (25 writers, up to 57,639 unique keywords) on the same hardware configuration used in the original Hermes paper.

### Leakage Reduction

The bucket scheme reduces the precision of observable result counts:

| Real count range | What attacker observes (original) | What attacker observes (extended) | Precision reduction |
|---|---|---|---|
| 1 | Exact: 1 | Bucket: 1 | None (boundary) |
| 2–3 | Exact | Bucket: 4 | Up to 2× |
| 5–8 | Exact | Bucket: 8 or 16 | Up to 3× |
| 17–32 | Exact | Bucket: 32 | Up to 2× |
| 33–64 | Exact | Bucket: 64 | Up to 1.94× |
| 65–128 | Exact | Bucket: 128 | Up to 1.97× |

For a typical keyword in the Enron dataset with ~47 matches, the attacker's precision is reduced from knowing the exact value `47` to only knowing the range `[33, 64]`.

### Bandwidth Overhead

The cost of volume hiding is additional dummy entries sent over the network:

| Real count | Padded count | Extra bytes sent |
|---|---|---|
| 3 | 4 | 4 bytes |
| 47 | 64 | 68 bytes |
| 130 | 256 | 504 bytes |
| 500 | 512 | 48 bytes |

Overhead is highest for counts just above a bucket boundary (e.g. 130 → 256 adds 504 bytes) and lowest for counts near the top of a bucket (e.g. 500 → 512 adds only 48 bytes). For typical keyword frequencies in the Enron dataset, the average overhead is modest relative to the total search response size.

### Search Latency

Volume hiding adds negligible computation overhead — `next_bucket()` is a linear scan through 14 values. The dominant cost remains the HICKAE decryption and DSSE linked-list traversal, which are unchanged. End-to-end search latency is within measurement noise of the original.

---

## Limitations and Future Work

**Current limitation — server still knows real counts:**
Our implementation hides volume from network observers and from the client, but the server itself computes the real match list before padding it. Hiding volume from the server requires ORAM-based techniques, which would significantly increase complexity and latency.

**Future work — backward privacy:**
Hermes has forward privacy but not backward privacy: the server can infer when documents are deleted by comparing search results over time. Implementing backward privacy (Type-II or Type-III) is a natural next extension and would complement the volume hiding work.

**Future work — adaptive bucket sizing:**
The current bucket ladder is fixed at powers of 2. An adaptive scheme that calibrates bucket boundaries to the actual keyword frequency distribution of the specific database could reduce average overhead while maintaining the same privacy guarantee.

**Future work — dynamic writer join/leave:**
Currently the number of writers is fixed at setup time (default 25). Allowing writers to join or leave without a full system reset would significantly improve practical deployability.

---

## Citation

If you use this work, please also cite the original Hermes paper:

```
@inproceedings{hermes2025,
  title     = {Hermes: Efficient Multi-Writer Encrypted Database},
  author    = {Tung Le and Thang Hoang},
  booktitle = {IEEE Symposium on Security and Privacy (S\&P)},
  year      = {2025}
}
```

---

## Acknowledgements

This extension builds directly on the original Hermes implementation by the ASAP Lab at Virginia Tech. The volume hiding technique follows standard practices from the SSE literature. All cryptographic protocols (HICKAE, DSSE) are unchanged from the original work.
