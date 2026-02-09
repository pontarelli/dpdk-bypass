sudo /home/vladimiro/dpdk_patched/dpdk-20.11/usertools/dpdk-devbind.py -u 16:00.0 16:00.1
sudo /home/andrea/pcimem/pcimem /sys/bus/pci/devices/0000\:16\:00.0/resource2  0x1000 w 0x1;
sudo /home/andrea/pcimem/pcimem /sys/bus/pci/devices/0000\:16\:00.0/resource2 0x2000 w 0x00010001;
sudo /home/andrea/pcimem/pcimem /sys/bus/pci/devices/0000\:16\:00.0/resource2 0x8014 w 0x1;
sudo /home/andrea/pcimem/pcimem /sys/bus/pci/devices/0000\:16\:00.0/resource2 0x800c w 0x1;
sudo /home/andrea/pcimem/pcimem /sys/bus/pci/devices/0000\:16\:00.0/resource2 0xC014 w 0x1;
sudo /home/andrea/pcimem/pcimem /sys/bus/pci/devices/0000\:16\:00.0/resource2 0xC00c w 0x1;
sudo /home/vladimiro/dpdk_patched/dpdk-20.11/usertools/dpdk-devbind.py -b vfio-pci 16:00.0 16:00.1
