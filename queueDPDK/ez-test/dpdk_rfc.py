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


def _append_to_log(log_path: str, data: str) -> int:
    with open(log_path, "a") as f:
        f.write(data)
    return 0

def _clear_file(log_path: str) -> int:
    with open(log_path, "w") as f:
        pass
    return 0

def _init_csv(csv_path: str, suite_cfg:json) -> int:

    fields = []
    fields.append("program")
    if suite_cfg.get("llc-ways"):
        fields.append("llc_way")
    fields.append("queues")
    fields.append("descriptors")
    fields.append("cms")
    fields.append("prefetch")
    fields.append("aggressive")

    # Create the CSV file and write the header
    with open(csv_path, "w",newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(fields)

def _init_csv_all(csv_path: str, suite_cfg:json) -> int:

    fields = []
    fields.append("repetition")
    fields.append("program")
    if suite_cfg.get("llc-ways"):
        fields.append("llc_way")
    fields.append("queues")
    fields.append("descriptors")
    fields.append("cms")
    fields.append("prefetch")
    fields.append("aggressive")

    # Create the CSV file and write the header
    with open(csv_path, "w",newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(fields)


def _append_to_csv(csv_path: str, data: list) -> int:
    with open(csv_path, "a") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(data)

def _get_all_pkts(dpdk_output) -> int:

    match = re.search(r'RX packets:\s*(\d+)', dpdk_output)
    if match:
        rx_packets = int(match.group(1))
        print("RX packets:", rx_packets)
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
    # print(f"mbl values: {mbl_values}")
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

def _load(program_path, cfg_dpdk_args, cfg_ifpci, cfg_app_args, cfg_queues, cfg_prefetch, cfg_aggressive, cfg_descriptors, cfg_cms, cfg_program_name) -> int:

    aggressive = "-a" if cfg_aggressive else ""

    cms = f"-c {cfg_cms}" if cfg_cms else ""
    descriptors = f"-d {cfg_descriptors}" if cfg_descriptors else ""
    prefetch = f"-p {cfg_prefetch}" if cfg_prefetch else ""

    cfg_marco = f",indirect_queues={cfg_queues}"

    command = f"sudo {program_path} {cfg_dpdk_args} -a {cfg_ifpci}{cfg_marco}"
    command += f" -- {cfg_app_args} -q {cfg_queues} {descriptors} {aggressive} {cms} {prefetch}"

    #se cms nel nome
    match cfg_program_name:
        case name if "marco" in name:
            command = f"sudo {program_path} {cfg_dpdk_args} -a {cfg_ifpci}{cfg_marco}"
            command += f" -- {cfg_app_args} -q {cfg_queues} {descriptors} {aggressive} {cms} {prefetch}"
            # prova sal skip
            # command = f"sudo {program_path} {cfg_dpdk_args} -a {cfg_ifpci}"
            # command += f" -- {cfg_app_args} -q {cfg_queues} {descriptors} {aggressive} {cms} {prefetch} -s 1000"

        case name if "cms" in name:
            command = f"sudo {program_path} {cfg_dpdk_args} -a {cfg_ifpci}"
            command += f" -- {cfg_app_args} -q {cfg_queues} {descriptors} {aggressive} {cms} {prefetch}"
        case name if "chain" or "asni" in name:
            command = f"sudo {program_path} {cfg_dpdk_args} -a {cfg_ifpci}"
            command += f" -- {cfg_app_args} -q {cfg_queues}"
            #sal skip
            # command += f" -- {cfg_app_args} -q {cfg_queues} -s 1000 -v"

    #se marco nel nome
    # se chain nel nome


    print(command)

    try:
        result = sp.run(shlex.split(command),capture_output=True,text=True, check=True)

    except sp.CalledProcessError as e:
        print("Error running load command:", e)
        return -1

    # print(result.stderr)
    # print(result.stdout)

    return True



def run_suite(suite_cfg:json, suite_name:str) -> int:

    logpath = os.path.join(os.getcwd(),"suites", suite_name, "log.txt")
    csvpath = os.path.join(os.getcwd(),"suites", suite_name, "results.csv")
    allcsvpath = os.path.join(os.getcwd(),"suites", suite_name, "all_results.csv")
    cfg_absolute_path = os.path.abspath(suite_cfg["exp-dir"])
    cfg_ifpci = suite_cfg["ifpci"]
    cfg_time = suite_cfg["time"]
    cfg_cpu = suite_cfg["cpu"]
    cfg_repetitions = suite_cfg["repetitions"]
    cfg_queues = suite_cfg["queues"]
    cfg_descriptors = suite_cfg.get("descriptors", [])
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
    _init_csv_all(allcsvpath,suite_cfg)
    print(f"CSV file initialized at {csvpath}")

    #clear logfile
    _clear_file(logpath)

    csvdata =[]
    allcsvdata = []


    cfg_program_path=os.path.join(cfg_absolute_path, cfg_programs[0]["path"])
    cfg_dpdk_args = cfg_programs[0]["dpdk-args"]
    cfg_app_args = cfg_programs[0]["app-args"]


    tot_iterations = cfg_repetitions * len(cfg_queues) * len(cfg_descriptors if cfg_descriptors else [None]) * len(cfg_cms if cfg_cms else [None]) * len(cfg_prefetch if cfg_prefetch else [None]) * len(cfg_aggressive) * (len(cfg_llc_way))
    tot_time = cfg_time * tot_iterations
    print(f"Total estimated time for the experiment: {tot_time} seconds (~{tot_time/60:.2f} minutes)")

    # Barra di progresso con tqdm
    with tqdm(total=tot_iterations, desc="Running experiments", unit="run") as pbar:
        for llc_way in cfg_llc_way:
            if llc_way:
                print(f"Setting LLC way to {llc_way}")
                _change_llc_way(llc_way)
            for queue in cfg_queues:
                for descriptor in cfg_descriptors if cfg_descriptors else [None]:
                    for cms in cfg_cms if cfg_cms else [None]:
                        for prefetch in cfg_prefetch if cfg_prefetch else [None]:
                            for aggressive in cfg_aggressive:
                                if (not aggressive and prefetch) or (aggressive and not prefetch):
                                    print(f"Skipping invalid combination: aggressive={aggressive}, prefetch={prefetch}")
                                    continue

                                reps_results = []

                                for rep in range(cfg_repetitions):
                                    metrics = {}

                                    allcsvdata.append(rep + 1)
                                    allcsvdata.append(cfg_programs[0]["name"])
                                    if llc_way:
                                        allcsvdata.append(llc_way)
                                    allcsvdata.append(queue)
                                    allcsvdata.append(descriptor)
                                    allcsvdata.append(cms)
                                    allcsvdata.append(prefetch)
                                    allcsvdata.append(aggressive)

                                    print(f"Running rep {rep + 1}/{cfg_repetitions} for program: {cfg_programs[0]['name']} with queues={queue}, descriptors={descriptor}, cms columns={cms}, prefetch={prefetch}, aggressive={aggressive}")

                                    start_time = time.time()
                                    # if cfg_perf:
                                    #     perf_data, throughput = _load_with_perf(
                                    #         cfg_cpu, cfg_perf, cfg_time, cfg_program_path,
                                    #         cfg_dpdk_args, cfg_ifpci, cfg_app_args,
                                    #         queue, prefetch, aggressive, descriptor, cms, cfg_per_pkt
                                    #     )
                                    _load(cfg_program_path, cfg_dpdk_args, cfg_ifpci, cfg_app_args,
                                            queue, prefetch, aggressive, descriptor, cms, suite_name )
                                    
                                    _append_to_csv(allcsvpath, allcsvdata)
                                    reps_results.append(metrics)
                                    allcsvdata.clear()

                                    pbar.update(1)
                                    elapsed = time.time() - start_time
                                    pbar.set_postfix({"Last run (s)": f"{elapsed:.1f}"})
                                # end repetitions
                                print(f"Completed {cfg_repetitions} repetitions for queues={queue}, descriptors={descriptor}, cms columns={cms}, prefetch={prefetch}, aggressive={aggressive}")
                                csvdata = []
                                csvdata.append(cfg_programs[0]["name"])
                                if llc_way:
                                    csvdata.append(llc_way)
                                csvdata.append(queue)
                                csvdata.append(descriptor)
                                if cfg_perf:
                                    csvdata.append(cms)
                                csvdata.append(prefetch)
                                csvdata.append(aggressive)

                                # Calcolo delle medie
                                if reps_results:
                                    # Prendo tutte le chiavi numeriche presenti
                                    keys = reps_results[0].keys()
                                    mean_metrics = {
                                    k: np.mean([r[k] for r in reps_results if k in r])
                                    for k in keys
                                }
                                std_metrics = {
                                    k: np.std([r[k] for r in reps_results if k in r])
                                    for k in keys
                                }

                                            
                                _append_to_csv(csvpath, csvdata)


    return 0