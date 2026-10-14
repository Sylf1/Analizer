import os
import requests
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import tkinter as tk
from tkinter import messagebox
import kagglehub
from urllib.parse import urlparse

# 1. CARGAR DATOS EN VIVO DESDE URLHAUS (Threat Intelligence)
print("Sincronizando base de datos global de URLhaus...")
URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/text_recent/"
urlhaus_malicious_urls = set()

try:
    response = requests.get(URLHAUS_FEED_URL, timeout=5)
    if response.status_code == 200:
        for line in response.text.splitlines():
            line = line.strip()
            # Ignorar comentarios del archivo
            if line and not line.startswith("#"):
                urlhaus_malicious_urls.add(line.lower())
        print(f"¡Sincronizado con éxito! {len(urlhaus_malicious_urls)} amenazas activas cargadas desde la nube.")
    else:
        print("No se pudo conectar a URLhaus, operando con listas locales e IA.")
except Exception as e:
    print("Modo offline: Sin conexión a internet para URLhaus. Usando red local.")

# 2. CARGAR EL DATASET DE KAGGLE PARA LA IA
print("Cargando dataset de Machine Learning...")
try:
    path = kagglehub.dataset_download("danielfernandon/web-page-phishing-dataset")
    archivo_csv = [os.path.join(path, f) for f in os.listdir(path) if f.endswith('.csv')][0]
    df = pd.read_csv(archivo_csv)
except Exception as e:
    df = None

# Entrenar el modelo
if df is not None:
    features = ['url_length', 'n_dots', 'n_hypens', 'n_at']
    X = df[features]
    y = df['phishing']

    modelo = RandomForestClassifier(n_estimators=100, random_state=42)
    modelo.fit(X, y)
    print("¡Modelo de IA entrenado y listo!\n")

# Listas de control secundarias (Tus hallazgos locales y trampas de hosting)
DOMINIOS_MALICIOSOS = [
    "v3rificar367.com",
    "login-actualizacion-seguridad.com",
    "banco-seguro-actualizar.com",
    "free-nitro-discord-gifts.com"
]

HOSTINGS_GRATUITOS = [
    "42web.io", "000webhostapp.com", "netlify.app", 
    "github.io", "vercel.app", "firebaseapp.com", 
    "iceiy.com", "core.windows.net", "gt.tc"
]

palabras_suspiciosas = [
    'login', 'verify', 'update', 'signin', 'confirm', 'password', 
    'v3rificar', 'v3rificacion', 'secure', 'msn', 'banco', 
    'validaciones', 'validacion', 'activacion', 'actualizar', 'cuenta',
    'confirmacion', 'c00nfirmaci0n'
]

# 3. FUNCIÓN DE ANÁLISIS MULTICAPA
def analizar_url():
    if df is None:
        messagebox.showerror("Error", "Falta el dataset de entrenamiento.")
        return
        
    url = entrada_url.get().strip()
    if not url:
        messagebox.showwarning("Advertencia", "Por favor ingresa una URL.")
        return
    
    url_limpia = url.lower()
    url_completa = url_limpia if "://" in url_limpia else "http://" + url_limpia
    parsed_url = urlparse(url_completa)
    netloc = parsed_url.netloc
    
    # CAPA 1: Verificar contra la base de datos global en vivo de URLhaus
    if url_limpia in urlhaus_malicious_urls or any(netloc in item for item in urlhaus_malicious_urls):
        resultado_label.config(text="¡ALERTA ROJA! Reportado en URLhaus (Malware/Phishing)", fg="red")
        return

    # CAPA 2: Lista Negra local
    if netloc in DOMINIOS_MALICIOSOS:
        resultado_label.config(text="¡ALERTA ROJA! Dominio en Lista Negra Local", fg="red")
        return

    # CAPA 3: Detección de Hosting Gratuito / Cloud con trampa
    es_hosting_gratis = any(hosting in netloc for hosting in HOSTINGS_GRATUITOS)
    tiene_palabra_clave = any(palabra in url_limpia for palabra in palabras_suspiciosas)

    if es_hosting_gratis and tiene_palabra_clave:
        resultado_label.config(text="¡ALERTA ROJA! Hosting gratuito con trampa detectado", fg="red")
        return

    # CAPA 4: Inteligencia Artificial (Random Forest)
    url_length = len(url)
    n_dots = url.count('.')
    n_hypens = url.count('-')
    n_at = url.count('@')
    
    entrada_df = pd.DataFrame([[url_length, n_dots, n_hypens, n_at]], 
                              columns=['url_length', 'n_dots', 'n_hypens', 'n_at'])
    
    prediccion = modelo.predict(entrada_df)
    
    if n_at > 0 or (prediccion[0] == 1 and tiene_palabra_clave):
        resultado_label.config(text="¡ALERTA! Posible Phishing detectado por IA", fg="red")
    else:
        resultado_label.config(text="La URL es Segura", fg="green")

# 4. INTERFAZ GRÁFICA (Tkinter)
root = tk.Tk()
root.title("CISO App - Detector de Phishing Multi-Capa")
root.geometry("500x320")

titulo = tk.Label(root, text="Detector de Phishing Definitivo", font=("Arial", 14, "bold"))
titulo.pack(pady=10)

label_inst = tk.Label(root, text="Ingresa la URL a analizar:")
label_inst.pack()

entrada_url = tk.Entry(root, width=58)
entrada_url.pack(pady=5)

boton_analizar = tk.Button(root, text="Analizar URL", command=analizar_url, bg="#cc0000", fg="white", font=("Arial", 10, "bold"))
boton_analizar.pack(pady=10)

resultado_label = tk.Label(root, text="", font=("Arial", 11, "bold"))
resultado_label.pack(pady=10)

root.mainloop()
