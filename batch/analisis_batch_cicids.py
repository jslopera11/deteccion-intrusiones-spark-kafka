"""
Procesamiento en batch del dataset CICIDS2017 con Apache Spark (PySpark).

Problema: detección de anomalías y tráfico malicioso en redes.
Este script caracteriza el tráfico benigno y los distintos tipos de ataque
(DoS, DDoS, escaneo de puertos, fuerza bruta, ataques web, botnet...) para
identificar los patrones que luego se vigilan en tiempo real con Kafka.

Etapas:
  1. Carga        : lee uno o varios CSV de CICIDS2017 (local o HDFS).
  2. Diagnóstico  : registros, nulos, infinitos, duplicados, valores negativos.
  3. Limpieza     : nombres de columna, infinitos, nulos, duplicados, negativos, etiquetas.
  4. Transformación: categoría de ataque, servicio por puerto, métricas derivadas.
  5. EDA          : DataFrames (agregaciones, estadísticas) y RDDs
                    (map, filter, flatMap, reduceByKey, groupByKey, collect, count, take, reduce).
  6. Resultados   : tablas CSV, dataset limpio en Parquet y gráficos PNG.

Uso:
  spark-submit analisis_batch_cicids.py --input ../data/cicids2017_muestra.csv --output ../output
  spark-submit analisis_batch_cicids.py --input hdfs://localhost:9000/Tarea3/cicids2017/ --output ../output
"""

import argparse
import csv
import os
import re

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

# Columnas de CICIDS2017 que usa el análisis (después de normalizar nombres)
COLUMNAS_NUMERICAS = [
    "destination_port", "flow_duration", "total_fwd_packets", "total_backward_packets",
    "total_length_of_fwd_packets", "total_length_of_bwd_packets", "flow_bytes_s",
    "flow_packets_s", "packet_length_mean", "syn_flag_count",
]
COLUMNAS_REQUERIDAS = COLUMNAS_NUMERICAS + ["label"]

SERVICIOS = {80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 53: "DNS", 8080: "HTTP-alt",
             139: "NetBIOS", 445: "SMB", 123: "NTP", 3389: "RDP", 444: "SNPP"}


def titulo(texto):
    print("\n" + "=" * 80 + f"\n{texto}\n" + "=" * 80)


def normalizar_nombre(nombre):
    """' Flow Bytes/s' -> 'flow_bytes_s'"""
    return re.sub(r"[^a-z0-9]+", "_", nombre.strip().lower()).strip("_")


def ruta_local(ruta):
    """Fuerza escritura en el disco local aunque Spark tenga HDFS como sistema por defecto."""
    return ruta if "://" in ruta else "file://" + os.path.abspath(ruta)


# ----------------------------------------------------------------------------
# 1. CARGA
# ----------------------------------------------------------------------------
def cargar(spark, ruta):
    titulo("1. CARGA DE DATOS")
    # Se lee todo como texto: así 'Infinity' y 'NaN' no rompen la lectura
    df = spark.read.option("header", True).option("inferSchema", False).csv(ruta)
    df = df.toDF(*[normalizar_nombre(c) for c in df.columns])

    faltantes = [c for c in COLUMNAS_REQUERIDAS if c not in df.columns]
    if faltantes:
        raise SystemExit(f"El archivo no tiene las columnas esperadas de CICIDS2017: {faltantes}")

    df = df.select(*COLUMNAS_REQUERIDAS)
    for c in COLUMNAS_NUMERICAS:
        df = df.withColumn(c, F.col(c).cast("double"))

    print(f"Origen: {ruta}")
    print(f"Columnas utilizadas ({len(df.columns)}): {', '.join(df.columns)}")
    return df


# ----------------------------------------------------------------------------
# 2. DIAGNÓSTICO
# ----------------------------------------------------------------------------
def diagnosticar(df):
    titulo("2. DIAGNÓSTICO DE CALIDAD")
    total = df.count()
    print(f"Registros totales: {total:,}")

    problemas = df.select(
        *[F.sum(F.col(c).isNull().cast("int")).alias(f"nulos_{c}") for c in ["flow_bytes_s", "flow_packets_s", "label"]],
        F.sum(F.isnan("flow_bytes_s").cast("int")).alias("nan_flow_bytes_s"),
        F.sum((F.col("flow_bytes_s") == float("inf")).cast("int")).alias("inf_flow_bytes_s"),
        F.sum((F.col("flow_packets_s") == float("inf")).cast("int")).alias("inf_flow_packets_s"),
        F.sum((F.col("flow_duration") < 0).cast("int")).alias("duracion_negativa"),
    ).collect()[0].asDict()
    for k, v in problemas.items():
        print(f"  {k:<22}: {v:,}")

    duplicados = total - df.dropDuplicates().count()
    print(f"  {'duplicados':<22}: {duplicados:,}")

    print("\nEtiquetas originales:")
    df.groupBy("label").count().orderBy(F.desc("count")).show(30, truncate=False)
    return total


# ----------------------------------------------------------------------------
# 3. LIMPIEZA
# ----------------------------------------------------------------------------
def limpiar(df):
    titulo("3. LIMPIEZA")
    inf = float("inf")
    limpio = (
        df
        # Infinitos y NaN -> nulos
        .withColumn("flow_bytes_s", F.when(F.isnan("flow_bytes_s") | (F.abs(F.col("flow_bytes_s")) == inf), None)
                    .otherwise(F.col("flow_bytes_s")))
        .withColumn("flow_packets_s", F.when(F.isnan("flow_packets_s") | (F.abs(F.col("flow_packets_s")) == inf), None)
                    .otherwise(F.col("flow_packets_s")))
        # Etiquetas: quitar espacios y reemplazar el carácter mal codificado de "Web Attack"
        .withColumn("label", F.trim(F.regexp_replace("label", r"[^\x20-\x7E]+", "-")))
        .dropna(subset=COLUMNAS_REQUERIDAS)
        .filter((F.col("flow_duration") >= 0) & (F.col("flow_bytes_s") >= 0))
        .dropDuplicates()
    )
    final = limpio.count()
    print("Acciones: infinitos/NaN a nulos, eliminación de nulos, duraciones negativas y duplicados,")
    print("          corrección de etiquetas 'Web Attack' con caracteres mal codificados.")
    print(f"Registros después de la limpieza: {final:,}")
    return limpio, final


# ----------------------------------------------------------------------------
# 4. TRANSFORMACIÓN
# ----------------------------------------------------------------------------
def transformar(df):
    titulo("4. TRANSFORMACIÓN")
    etiqueta = F.col("label")
    categoria = (
        F.when(etiqueta == "BENIGN", "Benigno")
        .when(etiqueta == "DDoS", "DDoS")
        .when(etiqueta.startswith("DoS"), "DoS")
        .when(etiqueta == "PortScan", "Escaneo de puertos")
        .when(etiqueta.endswith("Patator"), "Fuerza bruta")
        .when(etiqueta.startswith("Web Attack"), "Ataque web")
        .when(etiqueta == "Bot", "Botnet")
        .when(etiqueta == "Infiltration", "Infiltración")
        .when(etiqueta == "Heartbleed", "Heartbleed")
        .otherwise("Otro")
    )
    mapa_servicios = F.create_map(*[x for p, s in SERVICIOS.items() for x in (F.lit(p), F.lit(s))])

    df = (
        df
        .withColumn("destination_port", F.col("destination_port").cast("int"))
        .withColumn("categoria", categoria)
        .withColumn("es_ataque", (F.col("categoria") != "Benigno").cast("int"))
        .withColumn("servicio", F.coalesce(mapa_servicios[F.col("destination_port")], F.lit("Otro")))
        .withColumn("duracion_seg", F.col("flow_duration") / 1e6)  # CICIDS mide en microsegundos
        .withColumn("total_paquetes", F.col("total_fwd_packets") + F.col("total_backward_packets"))
        .withColumn("total_bytes", F.col("total_length_of_fwd_packets") + F.col("total_length_of_bwd_packets"))
        .withColumn("bytes_por_paquete",
                    F.when(F.col("total_paquetes") > 0, F.col("total_bytes") / F.col("total_paquetes")).otherwise(0.0))
        .withColumn("ratio_respuesta",  # paquetes de respuesta por paquete enviado
                    F.when(F.col("total_fwd_packets") > 0,
                           F.col("total_backward_packets") / F.col("total_fwd_packets")).otherwise(0.0))
    )
    print("Columnas nuevas: categoria, es_ataque, servicio, duracion_seg, total_paquetes,")
    print("                 total_bytes, bytes_por_paquete, ratio_respuesta")
    df.select("label", "categoria", "servicio", "duracion_seg", "total_paquetes",
              "total_bytes", "bytes_por_paquete").show(5, truncate=False)
    return df


# ----------------------------------------------------------------------------
# 5. ANÁLISIS EXPLORATORIO (DataFrames)
# ----------------------------------------------------------------------------
def eda_dataframes(df, total):
    titulo("5. ANÁLISIS EXPLORATORIO CON DATAFRAMES")
    resultados = {}

    print("5.1 Tráfico benigno vs malicioso")
    r = (df.groupBy(F.when(F.col("es_ataque") == 1, "Ataque").otherwise("Benigno").alias("tipo"))
         .count().withColumn("porcentaje", F.round(F.col("count") * 100 / total, 2))
         .orderBy(F.desc("count")))
    r.show(truncate=False)
    resultados["benigno_vs_ataque"] = r

    print("5.2 Registros por categoría y etiqueta")
    r = (df.groupBy("categoria", "label").count()
         .withColumn("porcentaje", F.round(F.col("count") * 100 / total, 3))
         .orderBy(F.desc("count")))
    r.show(30, truncate=False)
    resultados["conteo_por_etiqueta"] = r

    print("5.3 Perfil promedio de cada categoría")
    r = (df.groupBy("categoria")
         .agg(F.count("*").alias("flujos"),
              F.round(F.avg("duracion_seg"), 3).alias("duracion_prom_seg"),
              F.round(F.avg("total_paquetes"), 1).alias("paquetes_prom"),
              F.round(F.avg("bytes_por_paquete"), 1).alias("bytes_por_paquete_prom"),
              F.round(F.avg("ratio_respuesta"), 2).alias("ratio_respuesta_prom"),
              F.round(F.expr("percentile_approx(flow_bytes_s, 0.5)"), 1).alias("mediana_bytes_s"),
              F.countDistinct("destination_port").alias("puertos_distintos"))
         .orderBy(F.desc("flujos")))
    r.show(truncate=False)
    resultados["perfil_por_categoria"] = r

    print("5.4 Puertos de destino más atacados")
    r = (df.filter("es_ataque = 1").groupBy("destination_port", "servicio").count()
         .orderBy(F.desc("count")).limit(10))
    r.show(truncate=False)
    resultados["top_puertos_atacados"] = r

    print("5.5 Servicios: proporción de tráfico malicioso")
    r = (df.groupBy("servicio")
         .agg(F.count("*").alias("flujos"), F.sum("es_ataque").alias("ataques"))
         .withColumn("pct_ataque", F.round(F.col("ataques") * 100 / F.col("flujos"), 2))
         .orderBy(F.desc("ataques")))
    r.show(truncate=False)
    resultados["servicios"] = r

    print("5.6 Estadísticas descriptivas (benigno vs ataque)")
    for etiqueta, valor in (("Benigno", 0), ("Ataque", 1)):
        print(f"--- {etiqueta}")
        df.filter(F.col("es_ataque") == valor).select("duracion_seg", "total_paquetes", "bytes_por_paquete") \
          .summary("mean", "stddev", "min", "50%", "max").show(truncate=False)

    return resultados


# ----------------------------------------------------------------------------
# 5b. ANÁLISIS CON RDDs
# ----------------------------------------------------------------------------
def eda_rdd(df):
    titulo("5b. OPERACIONES CON RDDs")
    rdd = df.select("categoria", "destination_port", "total_bytes", "total_paquetes", "es_ataque").rdd

    # Transformaciones
    pares_bytes = rdd.map(lambda r: (r.categoria, r.total_bytes))             # map
    ataques = rdd.filter(lambda r: r.es_ataque == 1)                           # filter
    bytes_por_cat = pares_bytes.reduceByKey(lambda a, b: a + b)                # reduceByKey
    puertos_por_cat = ataques.map(lambda r: (r.categoria, r.destination_port)).groupByKey()  # groupByKey
    rangos = ataques.flatMap(lambda r: [                                       # flatMap: 1 flujo -> varias claves
        ("puerto_bien_conocido" if r.destination_port < 1024 else "puerto_alto", 1),
        ("flujo_pequeño" if r.total_paquetes <= 2 else "flujo_normal", 1),
    ]).reduceByKey(lambda a, b: a + b)

    # Acciones
    print(f"count()  -> flujos de ataque: {ataques.count():,}")
    total_bytes = rdd.map(lambda r: r.total_bytes).reduce(lambda a, b: a + b)
    print(f"reduce() -> bytes totales del dataset: {total_bytes / 1024 ** 3:,.2f} GB")
    print("take(3)  -> primeros pares (categoria, bytes):", pares_bytes.take(3))
    print("\ncollect() de reduceByKey -> MB transferidos por categoría:")
    for cat, b in sorted(bytes_por_cat.collect(), key=lambda x: -x[1]):
        print(f"  {cat:<20} {b / 1024 ** 2:>14,.1f} MB")
    print("\ngroupByKey -> puertos distintos atacados por categoría (y ejemplos):")
    for cat, puertos in sorted(puertos_por_cat.mapValues(set).collect()):
        print(f"  {cat:<20} {len(puertos):>5} puertos  ej: {sorted(puertos)[:8]}")
    print("\nflatMap + reduceByKey -> características de los flujos de ataque:")
    for k, v in sorted(rangos.collect()):
        print(f"  {k:<22} {v:,}")


# ----------------------------------------------------------------------------
# 6. RESULTADOS: CSV, Parquet y gráficos
# ----------------------------------------------------------------------------
def guardar(df, resultados, salida):
    titulo("6. GUARDADO DE RESULTADOS")
    carpeta = os.path.join(salida, "tablas")
    os.makedirs(carpeta, exist_ok=True)
    # Las tablas de resultados son pequeñas: se recogen en el driver y se guardan
    # como un único CSV cada una (sin carpetas part-0000 ni archivos _SUCCESS).
    for nombre, tabla in resultados.items():
        destino = os.path.join(carpeta, f"{nombre}.csv")
        with open(destino, "w", newline="", encoding="utf-8") as f:
            escritor = csv.writer(f)
            escritor.writerow(tabla.columns)
            escritor.writerows([list(fila) for fila in tabla.collect()])
        print(f"  CSV     -> {destino}")
    destino = os.path.join(salida, "cicids2017_limpio.parquet")
    df.coalesce(4).write.mode("overwrite").parquet(ruta_local(destino))
    print(f"  Parquet -> {destino}")


def graficar(resultados, salida):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    carpeta = os.path.join(salida, "graficos")
    os.makedirs(carpeta, exist_ok=True)
    azul, rojo, gris = "#2a6fb0", "#c8423b", "#8a8f98"
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})

    def guardar_fig(fig, nombre):
        ruta = os.path.join(carpeta, nombre)
        fig.tight_layout()
        fig.savefig(ruta, dpi=130)
        plt.close(fig)
        print(f"  Gráfico -> {ruta}")

    # 1. Benigno vs ataque
    filas = resultados["benigno_vs_ataque"].collect()
    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.barh([r.tipo for r in filas], [r["count"] for r in filas],
            color=[gris if r.tipo == "Benigno" else rojo for r in filas])
    for i, r in enumerate(filas):
        ax.text(r["count"], i, f"  {r.porcentaje} %", va="center")
    ax.set_title("Tráfico benigno vs malicioso")
    ax.set_xlabel("Flujos de red")
    guardar_fig(fig, "01_benigno_vs_ataque.png")

    # 2. Flujos por tipo de ataque (escala log)
    filas = [r for r in resultados["conteo_por_etiqueta"].collect() if r.label != "BENIGN"][::-1]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.barh([r.label for r in filas], [r["count"] for r in filas], color=rojo)
    ax.set_xscale("log")
    ax.set_title("Flujos por tipo de ataque (escala logarítmica)")
    ax.set_xlabel("Flujos de red")
    guardar_fig(fig, "02_flujos_por_ataque.png")

    # 3. Puertos más atacados
    filas = resultados["top_puertos_atacados"].collect()[::-1]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh([f"{r.destination_port} ({r.servicio})" for r in filas], [r["count"] for r in filas], color=azul)
    ax.set_title("Puertos de destino más atacados")
    ax.set_xlabel("Flujos maliciosos")
    guardar_fig(fig, "03_top_puertos_atacados.png")

    # 4. Perfil por categoría: paquetes promedio y duración promedio
    filas = resultados["perfil_por_categoria"].collect()
    nombres = [r.categoria for r in filas]
    colores = [gris if n == "Benigno" else rojo for n in nombres]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 4))
    a1.barh(nombres, [r.paquetes_prom for r in filas], color=colores)
    a1.set_title("Paquetes promedio por flujo")
    a2.barh(nombres, [r.duracion_prom_seg for r in filas], color=colores)
    a2.set_title("Duración promedio del flujo (s)")
    a2.set_yticklabels([])
    for a in (a1, a2):
        a.invert_yaxis()
    guardar_fig(fig, "04_perfil_por_categoria.png")

    # 5. Porcentaje de ataques por servicio
    filas = [r for r in resultados["servicios"].collect() if r.flujos > 0][::-1]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh([r.servicio for r in filas], [r.pct_ataque for r in filas], color=azul)
    ax.set_xlim(0, 100)
    ax.set_title("Porcentaje de tráfico malicioso por servicio")
    ax.set_xlabel("% de flujos que son ataques")
    guardar_fig(fig, "05_pct_ataque_por_servicio.png")


def main():
    parser = argparse.ArgumentParser(description="Análisis batch de CICIDS2017 con Spark")
    parser.add_argument("--input", default="../data/cicids2017_muestra.csv",
                        help="Archivo CSV o carpeta con varios CSV (local o hdfs://)")
    parser.add_argument("--output", default="../output", help="Carpeta local de resultados")
    parser.add_argument("--sin-graficos", action="store_true", help="No generar los PNG (si falta matplotlib)")
    args = parser.parse_args()

    spark = (SparkSession.builder.appName("CICIDS2017_Batch")
             .config("spark.sql.shuffle.partitions", "8")      # adecuado para una sola máquina virtual
             .config("spark.ui.showConsoleProgress", "false")  # salida de consola más limpia
             .getOrCreate())
    spark.sparkContext.setLogLevel("WARN")

    entrada = args.input if "://" in args.input or not os.path.exists(args.input) else ruta_local(args.input)
    df = cargar(spark, entrada)
    total_original = diagnosticar(df)
    df, total = limpiar(df)
    print(f"Registros eliminados: {total_original - total:,} ({(total_original - total) * 100 / total_original:.2f} %)")
    df = transformar(df).cache()

    resultados = eda_dataframes(df, total)
    eda_rdd(df)
    guardar(df, resultados, args.output)
    if not args.sin_graficos:
        graficar(resultados, args.output)

    titulo("PROCESO TERMINADO")
    spark.stop()


if __name__ == "__main__":
    main()
