#!/bin/bash
sudo mount -t hugetlbfs -o pagesize=2M nodev /mnt/huge
sudo dpdk-hugepages.py --reserve 20G --pagesize 2M --node 0
# NIC 0000:41:00.0 sits on NUMA socket 2: reserve hugepages there too so the
# mbuf pool can be allocated NUMA-local to the device instead of node 0 only.
sudo dpdk-hugepages.py --reserve 4G --pagesize 2M --node 2
