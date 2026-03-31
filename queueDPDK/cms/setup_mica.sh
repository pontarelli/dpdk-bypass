#!/bin/bash
sudo mount -t hugetlbfs -o pagesize=2M nodev /mnt/huge 
sudo dpdk-hugepages.py --reserve 10G --pagesize 2M --node 0
