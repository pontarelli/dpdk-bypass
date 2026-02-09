#!/bin/bash


cms_sizes=( 
  2
  1024
  2048
  4096
  8192
  16384
  32768
  65536
  $((65536*2))
  $((65536*4))
)


if [ -f run.txt ]; then
  rm run.txt
fi

if [ -f temp.txt ]; then
  rm temp.txt
fi

if [ -f temp_err.txt ]; then
  rm temp_err.txt
fi

echo -e "CMS Size\tThroughput\tLLC-loads\tLLC-load-misses\tLLC-stores" > run.txt

for x in ${cms_sizes[@]} ; do 
  #sudo perf stat -C 4 -e cycles,instructions,LLC-loads,LLC-load-misses,LLC-stores  --timeout 10000  ./build/cms -d librte_net_qdma.so -l 4-10 -n 4 -a 16:00.1 16:00.0  -- -a -p 1 -T 1 -q 1024 -c $x 2>temp_err.txt > temp.txt;  
  sudo perf stat -C 4 -e cycles,instructions,LLC-loads,LLC-load-misses,LLC-stores  --timeout 10000  ./build/cms -d librte_net_qdma.so -l 4 -n 4 -a 16:00.1 16:00.0  -- -p 1 -T 1 -q 1024 -c $x 2>temp_err.txt > temp.txt;  
  throu=$(cat temp.txt | egrep "Total Packets received" | tr -s ' ' | cut -d' ' -f6 | sed 's/,//g' | sed 's/)//g' | awk 'BEGIN {acc=0} {acc+=$1} END {print acc/NR}'); 
  llc_loads=$(cat temp_err.txt | egrep "LLC-loads" | tr -s ' ' | cut -d' ' -f 2 | sed 's/,//g')
  llc_load_misses=$(cat temp_err.txt | egrep "LLC-load-misses" | tr -s ' ' | cut -d' ' -f 2 | sed 's/,//g')
  llc_stores=$(cat temp_err.txt | egrep "LLC-stores" | tr -s ' ' | cut -d' ' -f 2 | sed 's/,//g')
  echo -e "$x\t$throu\t$llc_loads\t$llc_load_misses\t$llc_stores" >> run.txt;
  rm temp.txt; 
  rm temp_err.txt;
done;
