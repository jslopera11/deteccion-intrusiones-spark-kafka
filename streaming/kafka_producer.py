"""
Productor de Kafka: generador de tráfico de red simulado.

Cada evento representa un flujo de red (similar a un registro de CICIDS2017)
y se publica en formato JSON en el topic de Kafka (por defecto: trafico_red).

El tráfico es mayormente normal (BENIGN). De forma cíclica se inyectan
episodios de ataque, con las mismas etiquetas que usa CICIDS2017:
    - DoS Hulk     : un origen inunda el puerto 80 de un servidor.
    - PortScan     : un origen prueba muchos puertos distintos de un servidor.
    - SSH-Patator  : fuerza bruta contra SSH (puerto 22), muchos fallos de autenticación.
    - FTP-Patator  : fuerza bruta contra FTP (puerto 21), muchos fallos de autenticación.

Uso:
    python3 kafka_producer.py                     # envía a localhost:9092, topic trafico_red
    python3 kafka_producer.py --tasa 20           # eventos normales por segundo
    python3 kafka_producer.py --sin-kafka         # solo imprime (para probar sin Kafka)
"""

import argparse
import json
import random
import time

# ----------------------------------------------------------------------------
# Configuración de la red simulada
# ----------------------------------------------------------------------------
HOSTS_INTERNOS = [f"192.168.10.{i}" for i in range(100, 150)]     # 50 equipos de usuarios
SERVIDORES = ["192.168.10.3", "192.168.10.50", "192.168.10.51"]   # servidores internos
DESTINOS_EXTERNOS = [f"{random.randint(1, 223)}.{random.randint(0, 255)}."
                     f"{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(80)]
ATACANTES_EXTERNOS = ["205.174.165.73", "172.16.0.1", "45.155.205.233", "91.240.118.168"]

PUERTOS_NORMALES = [(443, "TCP", 0.55), (80, "TCP", 0.20), (53, "UDP", 0.15),
                    (22, "TCP", 0.04), (21, "TCP", 0.02), (3389, "TCP", 0.04)]

# Orden en que se presentan los ataques (útil para el video)
CICLO_ATAQUES = ["DoS Hulk", "PortScan", "SSH-Patator", "FTP-Patator"]
SEGUNDOS_NORMAL = 20     # tiempo de tráfico solo normal entre ataques
SEGUNDOS_ATAQUE = 25     # duración de cada episodio de ataque


def elegir_puerto_normal():
    r = random.random()
    acumulado = 0.0
    for puerto, protocolo, prob in PUERTOS_NORMALES:
        acumulado += prob
        if r <= acumulado:
            return puerto, protocolo
    return 443, "TCP"


def evento_normal():
    puerto, protocolo = elegir_puerto_normal()
    destino = random.choice(SERVIDORES) if puerto in (22, 21, 3389) else random.choice(DESTINOS_EXTERNOS)
    paquetes_fwd = random.randint(2, 40)
    paquetes_bwd = random.randint(1, 40)
    return {
        "src_ip": random.choice(HOSTS_INTERNOS),
        "dst_ip": destino,
        "dst_port": puerto,
        "protocol": protocolo,
        "flow_duration_ms": round(random.uniform(5, 3000), 2),
        "fwd_packets": paquetes_fwd,
        "bwd_packets": paquetes_bwd,
        "bytes": (paquetes_fwd + paquetes_bwd) * random.randint(60, 1400),
        "syn_flag": 1,
        "auth_failed": 1 if puerto in (21, 22) and random.random() < 0.05 else 0,
        "label": "BENIGN",
    }


def evento_ataque(tipo, atacante, victima):
    base = {"src_ip": atacante, "dst_ip": victima, "protocol": "TCP", "label": tipo}
    if tipo == "DoS Hulk":
        base.update(dst_port=80, flow_duration_ms=round(random.uniform(1, 50), 2),
                    fwd_packets=random.randint(80, 300), bwd_packets=random.randint(0, 5),
                    syn_flag=1, auth_failed=0)
        base["bytes"] = base["fwd_packets"] * random.randint(400, 1500)
    elif tipo == "PortScan":
        base.update(dst_port=random.randint(1, 1024), flow_duration_ms=round(random.uniform(0.01, 2), 3),
                    fwd_packets=1, bwd_packets=random.choice([0, 1]),
                    syn_flag=1, auth_failed=0)
        base["bytes"] = random.randint(40, 80)
    else:  # SSH-Patator / FTP-Patator (fuerza bruta)
        base.update(dst_port=22 if tipo == "SSH-Patator" else 21,
                    flow_duration_ms=round(random.uniform(100, 900), 2),
                    fwd_packets=random.randint(8, 20), bwd_packets=random.randint(6, 18),
                    syn_flag=1, auth_failed=1 if random.random() < 0.95 else 0)
        base["bytes"] = (base["fwd_packets"] + base["bwd_packets"]) * random.randint(60, 200)
    return base


# Eventos de ataque que se generan por cada evento normal (intensidad)
INTENSIDAD = {"DoS Hulk": 1.0, "PortScan": 0.8, "SSH-Patator": 0.5, "FTP-Patator": 0.5}


def main():
    parser = argparse.ArgumentParser(description="Generador de tráfico de red para Kafka")
    parser.add_argument("--broker", default="localhost:9092", help="Servidor Kafka (host:puerto)")
    parser.add_argument("--topic", default="trafico_red", help="Topic de destino")
    parser.add_argument("--tasa", type=float, default=20, help="Eventos normales por segundo")
    parser.add_argument("--sin-kafka", action="store_true", help="Solo imprime los eventos, sin enviarlos")
    args = parser.parse_args()

    producer = None
    if not args.sin_kafka:
        from kafka import KafkaProducer
        producer = KafkaProducer(
            bootstrap_servers=[args.broker],
            value_serializer=lambda x: json.dumps(x).encode("utf-8"),
        )
        print(f"Conectado a Kafka en {args.broker}. Publicando en el topic '{args.topic}'. Ctrl+C para detener.\n")

    pausa = 1.0 / args.tasa
    inicio = time.time()
    enviados = 0
    ataque_anterior = None

    try:
        while True:
            # Determinar en qué fase del ciclo estamos
            transcurrido = time.time() - inicio
            periodo = SEGUNDOS_NORMAL + SEGUNDOS_ATAQUE
            n_ciclo = int(transcurrido // periodo)
            en_ataque = (transcurrido % periodo) >= SEGUNDOS_NORMAL
            tipo = CICLO_ATAQUES[n_ciclo % len(CICLO_ATAQUES)] if en_ataque else None

            if tipo != ataque_anterior:
                if tipo:
                    atacante = random.choice(ATACANTES_EXTERNOS)
                    victima = random.choice(SERVIDORES)
                    print(f"\n>>> INICIA ATAQUE SIMULADO: {tipo} desde {atacante} hacia {victima}\n")
                else:
                    print("\n>>> Fin del ataque. Solo tráfico normal.\n")
                ataque_anterior = tipo

            eventos = [evento_normal()]
            if tipo:
                # Intensidad fraccionaria: se agrega 1 evento de ataque con esa probabilidad,
                # y la parte entera como eventos seguros.
                n = int(INTENSIDAD[tipo]) + (1 if random.random() < INTENSIDAD[tipo] % 1 else 0)
                eventos += [evento_ataque(tipo, atacante, victima) for _ in range(n)]

            for e in eventos:
                e["timestamp"] = time.time()
                if producer:
                    producer.send(args.topic, value=e)
                enviados += 1
                marca = "ATAQUE" if e["label"] != "BENIGN" else "normal"
                print(f"[{marca:6}] {e['src_ip']:>15} -> {e['dst_ip']:>15}:{e['dst_port']:<5} "
                      f"{e['label']:<12} paquetes={e['fwd_packets'] + e['bwd_packets']:<4} bytes={e['bytes']}")

            time.sleep(pausa)
    except KeyboardInterrupt:
        print(f"\nProductor detenido. Eventos enviados: {enviados}")
    finally:
        if producer:
            producer.flush()
            producer.close()


if __name__ == "__main__":
    main()
