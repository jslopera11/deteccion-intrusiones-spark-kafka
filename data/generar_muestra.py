"""
Genera un archivo de MUESTRA con el mismo formato de CICIDS2017 (MachineLearningCSV).

Sirve para probar el análisis batch sin descargar el dataset completo.
Reproduce las particularidades del archivo original:
  - nombres de columna con espacios al inicio (" Label", " Flow Duration", ...)
  - valores "Infinity" y "NaN" en Flow Bytes/s y Flow Packets/s
  - registros duplicados y algunas duraciones negativas
  - etiquetas de ataques web con un carácter mal codificado ("Web Attack � Brute Force")

Para el trabajo final se recomienda usar el dataset REAL (ver README).

Uso:
    python3 generar_muestra.py                 # 60.000 registros -> cicids2017_muestra.csv
    python3 generar_muestra.py --filas 200000
"""

import argparse
import csv
import random

COLUMNAS = [" Destination Port", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
            "Total Length of Fwd Packets", " Total Length of Bwd Packets", "Flow Bytes/s",
            " Flow Packets/s", " Packet Length Mean", " SYN Flag Count", " Fwd Header Length",
            " Fwd Header Length.1", " Label"]

# etiqueta: (proporción, puertos, rango duración µs, rango paquetes fwd, rango paquetes bwd, bytes/paquete)
PERFILES = {
    "BENIGN":                    (0.800, [443, 80, 53, 22, 21, 8080, 445, 139, 123, 3389], (100, 30_000_000), (1, 60), (0, 60), (60, 1200)),
    "DoS Hulk":                  (0.075, [80], (1, 2_000_000), (3, 12), (0, 8), (300, 1400)),
    "PortScan":                  (0.050, None, (1, 200), (1, 2), (0, 1), (0, 6)),
    "DDoS":                      (0.040, [80], (1, 5_000_000), (2, 8), (0, 6), (10, 1400)),
    "DoS GoldenEye":             (0.004, [80], (1_000, 11_000_000), (3, 10), (2, 8), (200, 1200)),
    "FTP-Patator":               (0.003, [21], (1_000, 8_000_000), (6, 12), (6, 14), (5, 30)),
    "SSH-Patator":               (0.003, [22], (1_000, 15_000_000), (10, 30), (10, 35), (40, 120)),
    "DoS slowloris":             (0.002, [80], (5_000_000, 100_000_000), (2, 6), (0, 3), (0, 300)),
    "DoS Slowhttptest":          (0.002, [80], (5_000_000, 100_000_000), (2, 6), (0, 3), (0, 300)),
    "Bot":                       (0.001, [8080, 80], (100, 1_000_000), (2, 6), (1, 5), (30, 300)),
    "Web Attack � Brute Force":  (0.0005, [80], (5_000, 6_000_000), (3, 10), (1, 6), (20, 500)),
    "Web Attack � XSS":          (0.0002, [80], (5_000, 6_000_000), (3, 10), (1, 6), (20, 600)),
    "Infiltration":              (0.0001, [444, 80, 443], (1_000, 60_000_000), (2, 200), (1, 200), (40, 1200)),
}


def fila(etiqueta):
    _, puertos, dur, fwd, bwd, bpp = PERFILES[etiqueta]
    puerto = random.randint(1, 1024) if puertos is None else random.choice(puertos)
    duracion = random.randint(*dur)
    p_fwd, p_bwd = random.randint(*fwd), random.randint(*bwd)
    b_fwd, b_bwd = p_fwd * random.randint(*bpp), p_bwd * random.randint(*bpp)
    if duracion == 0 or random.random() < 0.002:
        bytes_s, paquetes_s = random.choice(["Infinity", "NaN"]), "Infinity"
    else:
        bytes_s = round((b_fwd + b_bwd) / (duracion / 1e6), 4)
        paquetes_s = round((p_fwd + p_bwd) / (duracion / 1e6), 4)
    if random.random() < 0.0005:
        duracion = -1  # el dataset original tiene algunas duraciones negativas
    total_p = p_fwd + p_bwd
    media = round((b_fwd + b_bwd) / total_p, 4) if total_p else 0
    header = p_fwd * random.choice([20, 32, 40])
    return [puerto, duracion, p_fwd, p_bwd, b_fwd, b_bwd, bytes_s, paquetes_s, media,
            1 if random.random() < 0.3 else 0, header, header, etiqueta]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filas", type=int, default=60000)
    parser.add_argument("--salida", default="cicids2017_muestra.csv")
    args = parser.parse_args()

    random.seed(2017)
    etiquetas = list(PERFILES)
    pesos = [PERFILES[e][0] for e in etiquetas]
    filas = [fila(random.choices(etiquetas, pesos)[0]) for _ in range(args.filas)]
    filas += random.sample(filas, k=int(args.filas * 0.01))  # 1 % de duplicados
    random.shuffle(filas)

    with open(args.salida, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLUMNAS)
        w.writerows(filas)
    print(f"Muestra generada: {args.salida} ({len(filas)} registros)")


if __name__ == "__main__":
    main()
