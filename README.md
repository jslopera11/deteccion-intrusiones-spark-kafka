# Detección de anomalías y tráfico malicioso en redes con Apache Spark y Kafka

**Curso:** Big Data (202016911) – Universidad Nacional Abierta y a Distancia (UNAD)
**Actividad:** Tarea 3 – Procesamiento de Datos con Apache Spark
**Autor:** [Tu nombre completo] – Grupo 202016911_[número de grupo]

## Problema

En ciberseguridad y gestión de infraestructura, detectar una intrusión a tiempo es crítico. El análisis tradicional de logs de red por lotes deja ventanas de exposición peligrosas: las amenazas se descubren horas después de haber ocurrido.

Este proyecto aborda el problema en dos partes:

1. **Batch:** analiza el dataset CICIDS2017 con Spark para caracterizar cómo se comporta el tráfico benigno frente a cada tipo de ataque (DoS, DDoS, escaneo de puertos, fuerza bruta, ataques web, botnet, infiltración).
2. **Tiempo real:** simula un flujo continuo de eventos de red con Kafka y usa Spark Structured Streaming para detectar ataques DoS, escaneos de puertos y fuerza bruta en el momento en que ocurren.

## Conjunto de datos

- **Nombre:** CICIDS2017 – Intrusion Detection Evaluation Dataset
- **Fuente:** Canadian Institute for Cybersecurity, Universidad de New Brunswick (https://www.unb.ca/cic/datasets/ids-2017.html). También disponible en Kaggle (buscar "CICIDS2017").
- **Tamaño:** cerca de 2,8 millones de flujos de red en 8 archivos CSV (versión *MachineLearningCSV*), capturados durante 5 días laborales de julio de 2017.
- **Columnas:** 78 características por flujo (puerto de destino, duración, paquetes y bytes en cada sentido, tasas, banderas TCP…) y la etiqueta `Label` (BENIGN o el tipo de ataque).
- **Muestra incluida:** como el dataset completo supera el límite de GitHub, el repositorio incluye `data/generar_muestra.py`, que crea un archivo de 60.600 registros con el mismo formato (incluidos sus errores: espacios en los nombres de columna, valores `Infinity`, duplicados).

## Estructura del repositorio

```
├── batch/
│   └── analisis_batch_cicids.py      # Procesamiento en batch (limpieza, EDA, RDDs, gráficos)
├── streaming/
│   ├── kafka_producer.py             # Generador de tráfico de red con ataques simulados → Kafka
│   └── spark_streaming_consumer.py   # Detección de anomalías con Spark Structured Streaming
├── data/
│   ├── generar_muestra.py            # Genera una muestra con el formato de CICIDS2017
│   └── cicids2017_muestra.csv        # Muestra lista para usar
├── output/                           # Resultados de la ejecución batch
│   ├── graficos/*.png
│   ├── tablas/*.csv                  # Tablas de resultados
│   └── salida_consola.txt
├── GUIA_EJECUCION.md                 # Paso a paso en la máquina virtual + guion del video
└── requirements.txt
```

## 1. Procesamiento en batch

El script `batch/analisis_batch_cicids.py` usa DataFrames y RDDs de Spark en seis etapas:

| Etapa | Qué hace |
|---|---|
| Carga | Lee uno o varios CSV de CICIDS2017 desde HDFS o el disco local. Normaliza los nombres de columna (`" Flow Bytes/s"` → `flow_bytes_s`). |
| Diagnóstico | Cuenta registros, nulos, `NaN`, `Infinity`, duraciones negativas, duplicados y la distribución original de etiquetas. |
| Limpieza | Convierte infinitos a nulos y los elimina, quita duraciones negativas y duplicados, y corrige las etiquetas *Web Attack* con caracteres mal codificados. |
| Transformación | Agrega `categoria` (agrupa 15 etiquetas en 8 familias), `es_ataque`, `servicio` (según el puerto), `duracion_seg`, `total_paquetes`, `total_bytes`, `bytes_por_paquete` y `ratio_respuesta`. |
| EDA | Benigno vs. ataque, conteo por etiqueta, perfil promedio de cada categoría, puertos más atacados, porcentaje de ataques por servicio, estadísticas descriptivas. Con RDDs: `map`, `filter`, `flatMap`, `reduceByKey`, `groupByKey`, `count`, `reduce`, `take`, `collect`. |
| Resultados | 5 tablas CSV, dataset limpio en Parquet y 5 gráficos PNG. |

### Ejecución

```bash
# Con la muestra incluida
cd batch
spark-submit analisis_batch_cicids.py --input ../data/cicids2017_muestra.csv --output ../output

# Con el dataset real subido a HDFS (carpeta con los 8 CSV)
spark-submit --driver-memory 2g analisis_batch_cicids.py \
  --input hdfs://localhost:9000/Tarea3/cicids2017/ --output ../output
```

### Principales hallazgos

> Los resultados de `output/` corresponden a la muestra. Al ejecutar con el dataset real, actualice esta sección con sus cifras.

- Alrededor del 82 % de los flujos es tráfico benigno; los ataques más frecuentes son DoS Hulk, PortScan y DDoS.
- El puerto 80 (HTTP) concentra la gran mayoría de los ataques: es el objetivo de DoS, DDoS y ataques web.
- El escaneo de puertos tiene una firma muy clara: flujos de 1 a 2 paquetes, casi sin duración, dirigidos a cientos de puertos distintos.
- La fuerza bruta se concentra en los puertos 21 (FTP) y 22 (SSH), con flujos de tamaño medio y bytes por paquete bajos.
- Estos patrones se usan como reglas de detección en el procesamiento en tiempo real.

## 2. Procesamiento en tiempo real (Kafka + Spark Streaming)

- `kafka_producer.py` publica en el topic `trafico_red` unos 20 flujos de red por segundo en formato JSON (IP de origen y destino, puerto, protocolo, paquetes, bytes, fallos de autenticación y etiqueta). Alterna 20 segundos de tráfico normal con 25 segundos de ataque, en este orden: **DoS Hulk → PortScan → SSH-Patator → FTP-Patator**.
- `spark_streaming_consumer.py` lee el topic y, cada 10 segundos, muestra en consola:
  1. **Resumen de tráfico** por ventana de 1 minuto y tipo: flujos, paquetes y MB.
  2. **Alertas** por IP de origen, detectadas con reglas sobre cada ventana de 1 minuto:

| Alerta | Regla |
|---|---|
| Fuerza bruta | 20 o más fallos de autenticación |
| Escaneo de puertos | 25 o más puertos de destino distintos |
| DoS | 150 o más flujos hacia 3 o menos puertos |

La columna `etiquetas_reales` permite verificar que cada alerta corresponde al ataque que realmente se generó.

### Ejecución

```bash
# Crear el topic (solo la primera vez)
/opt/Kafka/bin/kafka-topics.sh --create --bootstrap-server localhost:9092 \
  --replication-factor 1 --partitions 1 --topic trafico_red

# Terminal 1: productor
python3 streaming/kafka_producer.py

# Terminal 2: consumidor (ajustar la versión a la de su Spark: spark-submit --version)
spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.3 streaming/spark_streaming_consumer.py
```

Las métricas se pueden ver en la interfaz web de Spark: `http://<IP-de-la-VM>:4040` (pestañas *Jobs*, *Stages* y *Structured Streaming*).

El paso a paso completo, incluida la solución a errores frecuentes, está en [GUIA_EJECUCION.md](GUIA_EJECUCION.md).

## Tecnologías

Apache Hadoop (HDFS) · Apache Spark 3.5 (PySpark, DataFrames, RDD, Structured Streaming) · Apache Kafka 3.9 · Python 3 · Matplotlib

## Referencia del dataset

Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP)*, 108–116.
