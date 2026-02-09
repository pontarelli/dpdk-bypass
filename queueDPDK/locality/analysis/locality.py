import csv
from collections import defaultdict
import math
# prima bisogna eseguire main.c > flows.txt

def burst_analysis(filename, output_csv):
    with open(filename, newline="") as f:
        reader = csv.reader(f)

        bursts = []
        burst_id = 0

        prev_queue = None
        prev_flow = None
        flows_in_burst = set()
        packets_in_burst = 0
        consecutive_count = 0
        max_consecutive = 0

        for row in reader:
            # se row[0] non è un intero, salta la riga
            if len(row) < 1:
                # print('Row is too short:', row)
                continue
            if not row[0].isdigit():
                # print('First element is not an integer:', row)
                continue
            queue = int(row[0])
            flow = tuple(row[1:])  # (src_ip, dst_ip, src_port, dst_port, protocol)

            # Se cambia coda → fine burst
            if prev_queue is not None and queue != prev_queue:
                # aggiorna massimo ultimo run del burst precedente
                max_consecutive = max(max_consecutive, consecutive_count)

                bursts.append({
                    "burst": burst_id,
                    "coda": prev_queue,
                    "flussi": len(flows_in_burst),
                    "pacchetti_consecutivi": max_consecutive,
                    "pacchetti_totali": packets_in_burst
                })
                burst_id += 1

                # reset variabili per nuovo burst
                flows_in_burst = set()
                packets_in_burst = 0
                consecutive_count = 0
                max_consecutive = 0
                prev_flow = None

            # Aggiorna informazioni burst corrente
            flows_in_burst.add(flow)
            packets_in_burst += 1

            # Conta pacchetti consecutivi uguali
            if flow == prev_flow:
                consecutive_count += 1
            else:
                consecutive_count = 1

            max_consecutive = max(max_consecutive, consecutive_count)

            prev_queue = queue
            prev_flow = flow

        # Aggiungi l’ultimo burst
        if prev_queue is not None:
            max_consecutive = max(max_consecutive, consecutive_count)
            bursts.append({
                "burst": burst_id,
                "coda": prev_queue,
                "flussi": len(flows_in_burst),
                "pacchetti_consecutivi": max_consecutive,
                "pacchetti_totali": packets_in_burst
            })

    # --- Scrivi in CSV ---
    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["burst","coda","flussi","pacchetti_consecutivi","pacchetti_totali"])
        writer.writeheader()
        for b in bursts:
            writer.writerow(b)


def flow_analysis(input_csv, output_csv):
    # Leggi i dati dei burst dal CSV precedente
    bursts_per_queue = defaultdict(list)

    with open(input_csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            queue = int(row["coda"])
            flows = int(row["flussi"])
            max_consec = int(row["pacchetti_consecutivi"])
            bursts_per_queue[queue].append((flows, max_consec))

    # Funzioni per media e deviazione standard
    def mean(lst):
        return sum(lst)/len(lst) if lst else 0

    def std(lst):
        if len(lst) < 2:
            return 0
        m = mean(lst)
        return math.sqrt(sum((x - m)**2 for x in lst)/(len(lst)-1))

    # Calcola statistiche per coda
    queue_stats = []
    all_flows = []
    all_consec = []

    for queue, data in bursts_per_queue.items():
        flows_list = [x[0] for x in data]
        consec_list = [x[1] for x in data]

        all_flows.extend(flows_list)
        all_consec.extend(consec_list)

        queue_stats.append({
            "coda": queue,
            "flussi_media": mean(flows_list),
            "flussi_std": std(flows_list),
            "pacchetti_consec_media": mean(consec_list),
            "pacchetti_consec_std": std(consec_list)
        })

    # Salva in CSV
    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["coda","flussi_media","flussi_std","pacchetti_consec_media","pacchetti_consec_std"])
        writer.writeheader()
        for q in queue_stats:
            writer.writerow(q)

    # --- Media totale tra tutte le code ---
    total_flows_mean = mean(all_flows)
    total_flows_std = std(all_flows)
    total_consec_mean = mean(all_consec)
    total_consec_std = std(all_consec)

    print(f"\nStatistiche per coda salvate in '{output_csv}'")
    print("--- Media totale tra tutte le code ---")
    print(f"Media numero flussi per burst: {total_flows_mean:.2f} std: {total_flows_std:.2f}")
    print(f"Media pacchetti consecutivi massimi per burst: {total_consec_mean:.2f} std: {total_consec_std:.2f}\n")

def analyze(input_csv, middle_csv, output_csv):
    burst_analysis(input_csv, middle_csv)
    flow_analysis(middle_csv, output_csv)

if __name__ == "__main__":
    for i in range(12):
        input_csv = f"input/{2**i}.txt"
        middle_csv = f"middle/burst{2**i}.csv"
        output_csv = f"output/flow{2**i}.csv"
        analyze(input_csv, middle_csv, output_csv)