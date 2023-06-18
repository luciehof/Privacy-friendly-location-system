#!/bin/bash

## The server must be running for this to work. 
## Must be run inside of the client


# python3 client.py get-pk
# python3 client.py register -u pseudo -S restaurant -S bar -S dojo

echo "Start tracing.\n\n"
date

for trace_num in $(seq 1 10)
do
  mkdir traces/$trace_num
  for grid_id in $(seq 1 100)
  do
    echo "====> Collecting grid$grid_id\_trace$trace_num.pcap"

    tcpdump -i lo 'port 9050' -w traces/$trace_num/grid$grid_id\_trace$trace_num.pcap &
    sleep 1

    echo "python3 client.py grid $grid_id -t> /dev/null"
    python3 client.py grid $grid_id -t > /dev/null
    sleep 2

    kill "$!"

    echo "--\n"
  done
done


echo "Tadaaaa !"
date