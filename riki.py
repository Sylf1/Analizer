import streamlit as st
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from urllib.parse import urlparse
import requests

st.set_page_config(page_title="CISO App - Detector de Phishing", page_icon="🛡️")

st.title("🛡️ CISO App - Detector de Phishing Multi-Capa")
st.write("Herramienta de análisis de URLs para seguridad de redes.")

# Cargar URLhaus (con caché para no saturar)
@st.cache_data(ttl=3600)
def cargar_urlhaus():
    urlhaus_set = set()
    try:
        res = requests.get("https://urlhaus.abuse.ch/downloads/text_recent/", timeout=5)
        if res.status_code == 200:
            for line in res.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    urlhaus_set.add(line.lower())
    except:
        pass
    return urlhaus_set

urlhaus_malicious_urls = cargar_urlhaus()

# Simular dataset y entrenar modelo de prueba (o puedes cargar tu CSV)
# Aquí usamos datos base para que el modelo funcione rápido en la nube
@st.cache_resource
def entrenar_modelo():
    # Datos de entrenamiento simulados basados en tus features
    data = {
        'url_length': [20, 50, 80, 25, 95, 30],
        'n_dots': [1, 4, 6, 2, 5, 1],
        'n_hypens': [0, 2, 4, 0, 3, 0],
        'n_at': [0, 0, 1, 0, 1, 0],
        'phishing': [0, 1, 1, 0, 1, 0]
    }
    df = pd.DataFrame(data)
    X = df[['url_length', 'n_dots', 'n_hypens', 'n_at']]
    y = df['phishing']
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    return model

modelo = entrenar_modelo()

DOMINIOS_MALICIOSOS = [
    "v3rificar367.com", "login-actualizacion-seguridad.com",
    "banco-seguro-actualizar.com", "free-nitro-discord-gifts.com"
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

url_input = st.text_input("Ingresa la URL a analizar:")

if st.button("Analizar URL"):
    if not url_input:
        st.warning("Por favor ingresa una URL.")
    else:
        url_limpia = url_input.lower()
        url_completa = url_limpia if "://" in url_limpia else "http://" + url_limpia
        parsed_url = urlparse(url_completa)
        netloc = parsed_url.netloc
        
        # Capas de análisis
        if url_limpia in urlhaus_malicious_urls or any(netloc in item for item in urlhaus_malicious_urls):
            st.error("¡ALERTA ROJA! Reportado en URLhaus (Malware/Phishing)")
        elif netloc in DOMINIOS_MALICIOSOS:
            st.error("¡ALERTA ROJA! Dominio en Lista Negra Local")
        else:
            es_hosting_gratis = any(h in netloc for h in HOSTINGS_GRATUITOS)
            tiene_palabra = any(p in url_limpia for p in palabras_suspiciosas)
            
            if es_hosting_gratis and tiene_palabra:
                st.error("¡ALERTA ROJA! Hosting gratuito con trampa detectado")
            else:
                # IA / Heurística
                url_length = len(url_input)
                n_dots = url_input.count('.')
                n_hypens = url_input.count('-')
                n_at = url_input.count('@')
                
                pred = modelo.predict([[url_length, n_dots, n_hypens, n_at]])
                
                if n_at > 0 or (pred[0] == 1 and tiene_palabra):
                    st.error("¡ALERTA! Posible Phishing detectado por IA")
                else:
                    st.success("La URL es Segura")