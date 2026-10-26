"""
Consumidor de Spark Structured Streaming: detección de tráfico anómalo en tiempo real.

Lee los eventos de red del topic de Kafka (trafico_red), los agrupa en ventanas
de 1 minuto y muestra en consola, cada 10 segundos:

  1. RESUMEN DE TRÁFICO por ventana y etiqueta: número de flujos, paquetes y bytes.
  2. ALERTAS por IP de origen, detectadas con reglas sobre la ventana:
       - Fuerza bruta : 20 o más fallos de autenticación (SSH/FTP).
       - Escaneo de puertos : 25 o más puertos de destino distintos.
       - DoS : 150 o más flujos con 3 o menos puertos de destino.
     La columna 'etiquetas_reales' permite comparar la detección con la
     etiqueta que trae el evento (como en CICIDS2017).

Ejecución (en la máquina virtual):
    spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.3 spark_streaming_consumer.py
"""

import argparse

from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    approx_count_distinct, col, collect_set, count, date_format, from_json,
    lit, round as sround, sum as ssum, when, window,
)
from pyspark.sql.types import (
    DoubleType, IntegerType, LongType, StringType, StructField, StructType,
)

# Umbrales de detección (por IP de origen, en una ventana de 1 minuto)
UMBRAL_FALLOS_AUTH = 20
UMBRAL_PUERTOS_DISTINTOS = 25
UMBRAL_FLUJOS_DOS = 150

ESQUEMA = StructType([
    StructField("src_ip", StringType()),
    StructField("dst_ip", StringType()),
    StructField("dst_port", IntegerType()),
    StructField("protocol", StringType()),
    StructField("flow_duration_ms", DoubleType()),
    StructField("fwd_packets", IntegerType()),
    StructField("bwd_packets", IntegerType()),
    StructField("bytes", LongType()),
    StructField("syn_flag", IntegerType()),
    StructField("auth_failed", IntegerType()),
    StructField("label", StringType()),
    StructField("timestamp", DoubleType()),
])


def parsear_eventos(df_kafka):
    """Convierte el valor binario de Kafka (JSON) en columnas tipadas."""
    return (
        df_kafka
        .select(from_json(col("value").cast("string"), ESQUEMA).alias("e"))
        .select("e.*")
        .withColumn("event_time", col("timestamp").cast("timestamp"))
        .withColumn("paquetes", col("fwd_packets") + col("bwd_packets"))
        .drop("timestamp")
    )


def resumen_trafico(eventos):
    """Flujos, paquetes y bytes por ventana de 1 minuto y tipo de tráfico."""
    return (
        eventos
        .groupBy(window(col("event_time"), "1 minute").alias("ventana"), col("label").alias("tipo_trafico"))
        .agg(
            count("*").alias("flujos"),
            ssum("paquetes").alias("paquetes"),
            ssum("bytes").alias("bytes"),
        )
        .select(
            date_format("ventana.start", "HH:mm:ss").alias("desde"),
            date_format("ventana.end", "HH:mm:ss").alias("hasta"),
            "tipo_trafico", "flujos", "paquetes",
            sround(col("bytes") / 1024 / 1024, 2).alias("MB"),
        )
    )


def detectar_anomalias(eventos):
    """Indicadores por IP de origen y ventana de 1 minuto + clasificación por reglas."""
    indicadores = (
        eventos
        .groupBy(window(col("event_time"), "1 minute").alias("ventana"), "src_ip")
        .agg(
            count("*").alias("flujos"),
            approx_count_distinct("dst_port").alias("puertos_distintos"),
            approx_count_distinct("dst_ip").alias("destinos_distintos"),
            ssum("auth_failed").alias("fallos_auth"),
            ssum("paquetes").alias("paquetes"),
            collect_set("label").alias("etiquetas_reales"),
        )
    )

    clasificado = indicadores.withColumn(
        "alerta",
        when(col("fallos_auth") >= UMBRAL_FALLOS_AUTH, lit("FUERZA BRUTA"))
        .when(col("puertos_distintos") >= UMBRAL_PUERTOS_DISTINTOS, lit("ESCANEO DE PUERTOS"))
        .when((col("flujos") >= UMBRAL_FLUJOS_DOS) & (col("puertos_distintos") <= 3), lit("DoS"))
    )

    return (
        clasificado
        .filter(col("alerta").isNotNull())
        .select(
            date_format("ventana.start", "HH:mm:ss").alias("desde"),
            date_format("ventana.end", "HH:mm:ss").alias("hasta"),
            "src_ip", "alerta", "flujos", "puertos_distintos",
            "fallos_auth", "paquetes", "etiquetas_reales",
        )
    )


def main():
    parser = argparse.ArgumentParser(description="Detección de anomalías de red con Spark Streaming")
    parser.add_argument("--broker", default="localhost:9092")
    parser.add_argument("--topic", default="trafico_red")
    args = parser.parse_args()

    spark = SparkSession.builder.appName("DeteccionIntrusionesStreaming").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    spark.conf.set("spark.sql.shuffle.partitions", "4")  # suficiente para una sola máquina

    df_kafka = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", args.broker)
        .option("subscribe", args.topic)
        .option("startingOffsets", "latest")
        .load()
    )

    eventos = parsear_eventos(df_kafka).withWatermark("event_time", "2 minutes")

    consulta_resumen = (
        resumen_trafico(eventos)
        .writeStream
        .queryName("resumen_trafico")
        .outputMode("update")
        .format("console")
        .option("truncate", "false")
        .trigger(processingTime="10 seconds")
        .start()
    )

    consulta_alertas = (
        detectar_anomalias(eventos)
        .writeStream
        .queryName("alertas")
        .outputMode("update")
        .format("console")
        .option("truncate", "false")
        .option("numRows", 50)
        .trigger(processingTime="10 seconds")
        .start()
    )

    print("Consumidor iniciado. Esperando eventos del topic", args.topic, "... (Ctrl+C para detener)")
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    main()
