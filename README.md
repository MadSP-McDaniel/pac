## Overview

This repo contains the source code for our paper "Efficient Storage Integrity in Adversarial Settings". The main contribution of the work is the design of a partially asynchronous integrity checking (PAC) algorithm, which performs integrity verifications (on block reads) synchronously and integrity updates (on block writes) asynchronously while sealing the integrity trust anchor (Merkle tree root) during flushes (fsync). Reference:
```
@inproceedings{bsb+25,
    title={{Efficient Storage Integrity in Adversarial Settings}},
    booktitle={{2025 IEEE Symposium on Security and Privacy (S&P)}},
    author={Quinn Burke and Ryan Sheatsley and Yohan Beugin and Eric Pauley and Owen Hines and Michael Swift and Patrick McDaniel},
    month={may},
    year={2025}
}
```

## Project structure

```
├── bench/         # benchmark and plotting scripts
└── src/           # source, test, and build files
```

## Environment setup

This repo requires installing several kernel modules. Setup on a physical or virtual machine is easiest. A convenience script `bench/scripts/setup_all.sh` is provided to ease setup. To use it:
1. Setup a new Ubuntu 20.04 machine (newer versions may work, but not tested) then clone this repo. The default kernel (i.e., Canonical's image) may be 5.4, in which case you should install AWS's 5.15 kernel image (compatible with Ubuntu 20.04, BDUS, other kmod dependencies, and can run on AWS), then reboot: <!-- (compatible with Ubuntu 20.04, BDUS, dm-ebs kmod, dm-writeboost kmod, dm-writecache kmod, dm-verity kmod, and can run on AWS) -->
    ```bash
    > cd bench/scripts
    > ./setup_all -1 (optional, installs zsh)
    > ./setup_all 0 (installs kernel 5.15)
    (reboot)
    > ./setup_all 1 (builds and installs all other dependencies)
    ```
2. The next step is to setup the disks. The code assumes the presence of at least two disks: a data disk and metadata disk. They can be physically distinct disks, physical partitions, or logical partitions. Edit the last code block in the convenience script based on what hardware is available to your machine (names and sizes). For example, the default commands assume you have one additional NVMe disk attached to the machine (not the boot disk/partition) called `/dev/nvme1n1`. The commands setup two logical partitions (as linear device mapper targets), one that will store data and one that will store metadata. Once you have edited the script appropriately, run:
    ```bash
    > ./setup_all 2
    ```
    After running the script, you should see the logical partitions: `/dev/mapper/data_dev` and `/dev/mapper/metadata_dev`. Check with `lsblk`. Further partitions (for leaf and internal tree nodes) will be created on this top-level metadata disk automatically in the benchmark scripts. When running experiments, you should see the logical partitions: `/dev/mapper/data_disk` (for encrypted data blocks), `/dev/mapper/top_leaf_meta_disk` (for metadata blocks containing leaf nodes), and `/dev/mapper/top_internal_meta_disk` (for metadata blocks containing internal nodes). The benchmark scripts will automatically setup disks and clean up these disks. However, you can clean up the disks manually at any time with: 
    ```bash
    > ./setup_disks_raw.sh c
    ```

## Usage

In the following, we assume that the three disks listed above are setup and ready to use. Navigate to `bench/`. (Note: adjust usage of sudo where necessary.)

### Using the driver interactively
1. (from terminal 1) Build the dmt driver:
    ```bash
    > cd src && make clean && make CXXFLAGS="-DFIXED_ARITY=2" (change arity to examine high-degree trees)
    ```
2. (from terminal 1) Try the unit test, which executes a workload by calling the block device handlers directly (see `test.cc` for details on command line args):
    ```bash
    > ./dmt_test -u 0 -b /dev/mapper/data_disk -m /dev/mapper/top_leaf_meta_disk \ 
        -s /dev/mapper/top_internal_meta_disk -k 1 -a 2 -x 0 -c 0.1 -i 0.0 -p 1000 \ 
        -q 100 -w 0.75 -t 4 -z 1.5 -r 0.01
    ```
    The args are largely the same as below, with the addition of `-r` (read ratio) and `-z` (zipf parameter).
3. (from terminal 1) Try initializing a real block device (`/dev/bdus-XXX`, which wraps the data and metadata disks and is registered to the kernel):
    ```bash
    > sudo DMT_HOME=<dmt root> <dmt root>/src/dmt -u 0 \
        -b /dev/mapper/data_disk -m /dev/mapper/top_leaf_meta_disk \
        -s /dev/mapper/top_internal_meta_disk -k 1 -a 2 -x 0 -c 0.1 \
        -i 0.0 -p 1000 -q 100 -w 0.75 -t 4
    ```
    From here, you can check that the device is listed with `lsblk`. Like other devices attached to the system, you can also format a file system on top and run applications. The driver will transparently encrypt data and verify/update hashes in the hash tree. If the merkle tree type specified (via the `-t` arg) represents the DMT type, the driver will execute verifications and updates using the DMT algorithm. Running different benchmarks will show that the disks protected by DMTs have higher performance than those protected by other hash tree types (or arities).

### Running the benchmark scripts
1. (from terminal 2)  The `bench.sh` script allows specifying a range of experiment parameters to run (e.g., merkle tree type, workload type, capacity, whether to format a file system, etc.). It will setup disk and run the workloads using the standard benchmarking tools `fio` or `filebench`. See the script for details and configuration. To run the full benchmark suite, first initialize a block device via the above command, then run:
    ```bash
    > cd bench && ./bench.sh
    ```
    Once the benchmark is complete, you can destroy the BDUS device with:
    ```bash
    > sudo bdus destroy /dev/bdus-XXX
    ```
