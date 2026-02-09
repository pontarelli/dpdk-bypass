import csv
import json
import os
import re
import shlex
import signal
import subprocess as sp
import threading
import numpy as np
from time import sleep
from hooks import before_exp, after_exp
import psutil
from tqdm import tqdm
import time
import statistics



def _append_to_log(log_path: str, data: str) -> int:
    with open(log_path, "a") as f:
        f.write(data)
    return 0

def _clear_file(log_path: str) -> int:
    with open(log_path, "w") as f:
        pass
    return 0

def _init_csv(csv_path: str, suite_cfg: json) -> int:

    fields = []

    is_all = "all" in csv_path      # CSV di tutte le ripetizioni?
    has_perf = suite_cfg.get("perf")
    has_llc = suite_cfg.get("llc-ways")
    has_ooo = suite_cfg.get("out_of_order")

    # ---- CASO CSV PERF / CSV MEDIE ----
    if has_perf:
        fields.append("program")
        if is_all:
            fields.append("repetition")
        if has_llc:
            fields.append("llc_way")
        fields.append("queues")
        fields.append("descriptors")
        fields.append("cms")
        fields.append("prefetch")
        fields.append("aggressive")

        if is_all:
            # CSV "all" → valori diretti
            fields.append("throughput")
            fields.extend(suite_cfg.get("perf", []))
            fields.append("max_bw")
            fields.append("avg_bw")
        else:
            # CSV finale → media e std alternati
            metrici = ["throughput"] + suite_cfg.get("perf", []) + ["max_bw", "avg_bw"]

            for m in metrici:
                fields.append(f"{m}_mean")
                fields.append(f"{m}_std")

    # ---- CASO OUT-OF-ORDER / CSV MEDIE E STD ----
    elif has_ooo:
        fields.append("program")
        fields.append("queues")
        fields.append("descriptors")
        fields.append("prefetch")
        fields.append("aggressive")

        if is_all:
            # CSV "all"
            fields.append("throughput")
            fields.append("total")
            fields.append("in_order")
            fields.append("out_of_order")
            fields.append("percentage_out_of_order")
        else:
            # CSV finale (media + std alternati)
            metrici = ["throughput", "total", "in_order", "out_of_order", "percentage_out_of_order"]
            for m in metrici:
                fields.append(f"{m}_mean")
                fields.append(f"{m}_std")

    # ---- Scrittura header ----
    with open(csv_path, "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(fields)
    return 0

def _append_to_csv(csv_path: str, data: list) -> int:
    with open(csv_path, "a") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(data)

def _get_all_pkts(dpdk_output) -> int:

    match = re.search(r'RX packets:\s*(\d+)', dpdk_output)
    if match:
        rx_packets = int(match.group(1))
        # print("RX packets:", rx_packets)
    else:
        rx_packets = -1
        print("RX packets not found.")
    
    return rx_packets

def _get_dpdk_throughput(dpdk_output) -> int:

    match = re.search(r'measured RX Throughput:\s*(\d+)', dpdk_output)
    if match:
        rx_packets = int(match.group(1))
        print("Throughput:", rx_packets)
    else:
        rx_packets = -1
        print("RX packets not found.")
    
    return rx_packets

def _parse_perf_output(perf_output: str) -> dict:

    perf_data = {}
    for line in perf_output.strip().splitlines():
    # Usa una regex per catturare numero ed evento
        match = re.match(r'\s*([\d,]+)\s+([^\s#(]+)', line)
        if match:
            number = match.group(1).replace(',', '')
            event = match.group(2)
            perf_data[event] = int(number)
    return perf_data

def parse_bw(output: str) -> float:
    mbl_values = []
    lines = output.strip().splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("CORE") or line.startswith("TIME") or not line:
            continue  # salta intestazioni e righe non rilevanti
        parts = line.split()
        if len(parts) > 0:
            try:
                mbl = float(parts[3])
                mbl_values.append(mbl)
            except ValueError:
                continue
    if not mbl_values:
        raise ValueError("Nessun valore MBL trovato.")

    mbl_values = mbl_values[4:]  # Ignora i prmi 4 valori che sono spesso anomali

    avg_mbl = sum(mbl_values) / len(mbl_values)
    max_mbl = max(mbl_values)
    print(f"mbl values: {mbl_values}")
    return max_mbl, avg_mbl

def _get_bw(cfg_cpu, cfg_time, result_bw) -> int:

    command = f"sudo pqos -m 'mbl:{cfg_cpu}' -t {int(cfg_time/2)}"
    # print("Running bandwidth command:", command)
    try:
        result = sp.run(shlex.split(command), capture_output=True, text=True, check=True)
    except sp.CalledProcessError as e:
        print("Error running pqos command:", e)
        return -1
    max_bw, avg_bw = parse_bw(result.stdout)

    result_bw["max_bw"] = max_bw
    result_bw["avg_bw"] = avg_bw
    return 0

def _change_llc_way(llc_way: int) -> int:
    command = f"sudo wrmsr -a 0xc8b 0x{llc_way}"
    try:
        result = sp.run(shlex.split(command), capture_output=True, text=True, check=True)
    except sp.CalledProcessError as e:
        print("Error changing LLC way:", e)
        return -1
    return 0

def _load_with_perf(cfg_cpu, cfg_perf, cfg_time, program_path, cfg_dpdk_args ,cfg_ifpci, cfg_app_args, cfg_queues, cfg_prefetch, cfg_aggressive, cfg_descriptors, cfg_cms, cfg_per_pkt, prog_name) -> int:

    #sudo perf stat -C 4 -e cycles,instructions,cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,L1-dcache-stores,
    # l2_request.miss,l2_request.all,dTLB-loads,dTLB-load-misses,LLC-loads,LLC-load-misses,LLC-stores
    #   --timeout 2000  ./build/cms -d librte_net_qdma.so -l 4-10 -n 4 -a 16:00.1 16:00.0  -- -p 1 -T 1 -q 1

    aggressive = "-a" if cfg_aggressive else ""
    perf_timeout = cfg_time * 1000  # Convert to milliseconds
    perf_events = ",".join(cfg_perf)
    cms = f"-c {cfg_cms}" if cfg_cms else ""

    match prog_name:
        case name if "asni" in name:
            command = f"sudo perf stat -C {cfg_cpu} -e {perf_events} --timeout {perf_timeout} {program_path} {cfg_dpdk_args} -a {cfg_ifpci}"
            command += f" -- {cfg_app_args} -q {cfg_queues}"
        case _:
            command = f"sudo perf stat -C {cfg_cpu} -e {perf_events} --timeout {perf_timeout} {program_path} {cfg_dpdk_args} -a {cfg_ifpci}"
            command += f" -- {cfg_app_args} -q {cfg_queues} -d {cfg_descriptors} {aggressive} {cms} -p {cfg_prefetch}"
    print(command)

    #lancia un thread diverso per calcolare la banda
    result_bw = {"max_bw": 0, "avg_bw": 0}
    thread = threading.Thread(target=_get_bw, args=(cfg_cpu, cfg_time, result_bw))
    thread.start()

    try:
        result = sp.run(shlex.split(command),capture_output=True,text=True, check=True)

    except sp.CalledProcessError as e:
        print("Error running perf command:", e)
        return -1
    
    thread.join()  # Attende il thread che calcola la banda

    max_bw = result_bw["max_bw"]
    avg_bw = result_bw["avg_bw"]
    
    
    # print(result.stderr)
    # print(result.stdout)
    perf_data = _parse_perf_output(result.stderr)
    # print(perf_data)
    throughput = _get_dpdk_throughput(result.stdout)
    all_pkts = _get_all_pkts(result.stdout)
    if throughput <= 0:
        print("Error: Throughput is zero or negative")
        throughput = 1

    if cfg_per_pkt:
        perf_data_per_pkt = {k: v/ all_pkts for k, v in perf_data.items()}
        perf_data = perf_data_per_pkt

    perf_data["max_bw"] = max_bw
    perf_data["avg_bw"] = avg_bw
    # print("Perf data:", perf_data)

    return perf_data, throughput

def _out_of_order(program_path, cfg_dpdk_args, cfg_ifpci, cfg_app_args, cfg_queues, cfg_prefetch, cfg_aggressive, cfg_descriptors) -> int:
    aggressive = "-a" if cfg_aggressive else ""


    command = f"sudo {program_path} {cfg_dpdk_args} -a {cfg_ifpci}"
    command += f" -- {cfg_app_args} -q {cfg_queues} -d {cfg_descriptors} {aggressive} -p {cfg_prefetch}"
    # print(command)

    try:
        result = sp.run(shlex.split(command), capture_output=True, text=True, check=True)
    except sp.CalledProcessError as e:
        print("Error running out-of-order test command:", e)
        return -1

    # print(result.stdout)
    # print(result.stderr)
    # Trova tutte le occorrenze dei blocchi con in order / out of order
    pattern = r'in order:\s+([\d,]+)\s+out of order:\s+([\d,]+)'
    matches = re.findall(pattern, result.stdout)

    if not matches:
        return None, None

    # Prendi l'ultima corrispondenza
    in_order_str, out_of_order_str = matches[-1]

    # Rimuovi le virgole e converti in interi
    in_order = int(in_order_str.replace(',', ''))
    out_of_order = int(out_of_order_str.replace(',', ''))

    throughput = _get_dpdk_throughput(result.stdout)
    if throughput <= 0:
        print("Error: Throughput is zero or negative")
        throughput = 1


    print(f"In order: {in_order}, Out of order: {out_of_order}")

    tot = in_order + out_of_order

    return throughput,tot, in_order ,out_of_order

def run_suite(suite_cfg:json, name:str) -> int:

    logpath = os.path.join(os.getcwd(),"suites", name, "log.txt")
    csvpath = os.path.join(os.getcwd(),"suites", name, "results.csv")
    allcsvpath = os.path.join(os.getcwd(),"suites", name, "all_results.csv")
    cfg_absolute_path = os.path.abspath(suite_cfg["exp-dir"])
    cfg_ifpci = suite_cfg["ifpci"]
    cfg_time = suite_cfg["time"]
    cfg_cpu = suite_cfg["cpu"]
    cfg_repetitions = suite_cfg["repetitions"]
    cfg_queues = suite_cfg["queues"]
    cfg_descriptors = suite_cfg["descriptors"]
    cfg_throughput = suite_cfg["throughput"]
    cfg_perf = suite_cfg.get("perf", [])
    cfg_per_pkt = suite_cfg.get("per-pkt",True)
    cfg_programs = suite_cfg["progs"]
    cfg_cms = suite_cfg.get("cms", [])
    cfg_aggressive = suite_cfg.get("aggressive", [False])
    cfg_prefetch = suite_cfg.get("prefetch", [0])
    cfg_out_of_order = suite_cfg.get("out-of-order", False)
    cfg_llc_way = suite_cfg.get("llc-ways", [None])
    #clear csv and sets up fiels
    # _init_csv(csvpath, cfg_perf, cfg_out_of_order)
    _init_csv(csvpath,suite_cfg)
    _init_csv(allcsvpath,suite_cfg)

    print(f"CSV file initialized at {csvpath}")

    #clear logfile
    _clear_file(logpath)

    csvdata =[]
    allcsvdata = []


    cfg_program_path=os.path.join(cfg_absolute_path, cfg_programs[0]["path"])
    cfg_dpdk_args = cfg_programs[0]["dpdk-args"]
    cfg_app_args = cfg_programs[0]["app-args"]


    tot_iterations = cfg_repetitions * len(cfg_queues) * len(cfg_descriptors) * len(cfg_cms if cfg_cms else [None]) * len(cfg_prefetch) * len(cfg_aggressive) * (len(cfg_llc_way))
    tot_time = cfg_time * tot_iterations

    print(f"Total estimated time for the experiment: {tot_time} seconds (~{tot_time/60:.2f} minutes)")

    with tqdm(total=tot_iterations, desc="Running experiments", unit="run") as pbar:
        for llc_way in cfg_llc_way:
            if llc_way:
                print(f"Setting LLC way to {llc_way}")
                _change_llc_way(llc_way)
            for queue in cfg_queues:
                for descriptor in cfg_descriptors:
                    for cms in cfg_cms if cfg_cms else [None]:
                        for prefetch in cfg_prefetch:
                            for aggressive in cfg_aggressive:

                                csvdata.append(cfg_programs[0]["name"])
                                if llc_way:
                                    csvdata.append(llc_way)
                                csvdata.append(queue)
                                csvdata.append(descriptor)
                                if cfg_perf:
                                    csvdata.append(cms)
                                csvdata.append(prefetch)
                                csvdata.append(aggressive)
                                runs_all = []   # qui mettiamo solo i valori numerici delle ripetizioni

                                for rep in range(cfg_repetitions):
                                    print(f"Repetition {rep+1}/{cfg_repetitions}")
                                    print(f"Running program: {cfg_programs[0]['name']} with queues={queue}, descriptors={descriptor}, cms columns={cms}, prefetch={prefetch}, aggressive={aggressive}")

                                    csvdata_rep = csvdata.copy()
                                    csvdata_rep.insert(1, rep+1)
                                    allcsvdata.extend(csvdata_rep)

                                    start_time = time.time()

                                    row_rep = []   # raccolgo dati numerici della singola ripetizione

                                    if cfg_perf:
                                        perf_data, throughput = _load_with_perf(
                                            cfg_cpu, cfg_perf, cfg_time, cfg_program_path,
                                            cfg_dpdk_args, cfg_ifpci, cfg_app_args,
                                            queue, prefetch, aggressive, descriptor, cms,
                                            cfg_per_pkt, cfg_programs[0]['name']
                                        )

                                        allcsvdata.append(throughput)
                                        row_rep.append(throughput)

                                    if cfg_out_of_order:
                                        throughput, tot, in_order, out_of_order = _out_of_order(
                                            cfg_program_path, cfg_dpdk_args, cfg_ifpci,
                                            cfg_app_args, queue, prefetch, aggressive, descriptor
                                        )

                                        allcsvdata.extend([
                                            throughput,
                                            tot,
                                            in_order,
                                            out_of_order,
                                            out_of_order / tot if tot > 0 else 0
                                        ])

                                        row_rep.extend([throughput, tot, in_order, out_of_order])

                                    if cfg_perf:
                                        allcsvdata.extend(perf_data.values())
                                        row_rep.extend(perf_data.values())

                                    # Salvo tutti i dati della singola ripetizione in allcsv
                                    _append_to_csv(allcsvpath, allcsvdata)
                                    allcsvdata.clear()

                                    # aggiungo alla lista globale per media/std
                                    runs_all.append(row_rep)

                                    pbar.update(1)
                                    elapsed = time.time() - start_time
                                    pbar.set_postfix({"Last run (s)": f"{elapsed:.1f}"})


                                # ---- DOPO LE RIPETIZIONI ----

                                # Trasponi per colonna
                                columns = list(zip(*runs_all))

                                # Calcola media e std
                                means = [statistics.mean(col) for col in columns]
                                stds  = [statistics.stdev(col) if len(col) > 1 else 0 for col in columns]

                                # Alterna media/std → [m1, s1, m2, s2, m3, s3, ...]
                                mean_std_pairs = []
                                for m, s in zip(means, stds):
                                    mean_std_pairs.extend([m, s])

                                # Riga finale per il CSV
                                csvdata_final = csvdata.copy()
                                csvdata_final.extend(mean_std_pairs)

                                _append_to_csv(csvpath, csvdata_final)

                                
    return 0