# 🛡️ URL Phishing Analyzer (Prototipo de Escritorio)

Una herramienta de escritorio en Python diseñada para evaluar enlaces y detectar posibles indicadores de phishing mediante un enfoque multicapa, desarrollada como prototipo académico para la materia de **Sistemas Colaborativos**.

---

## ⚠️ Aclaración Importante / Descargo de Responsabilidad

> **Nota:** Este software es **únicamente un prototipo con fines educativos y de demostración académica**. No es un sistema de seguridad infalible ni reemplaza a un antivirus o motor de análisis profesional. Se diseñó como un ejemplo práctico para entender la estructura de las URLs maliciosas y fomentar buenas prácticas de seguridad.

---

## 📌 Descripción del Proyecto

En el contexto de la materia **Sistemas Colaborativos**, este desarrollo acompaña a un sitio web informativo en Google Sites para coordinar, documentar y concienciar sobre la seguridad digital y la detección de amenazas cibernéticas en equipos de trabajo.

La aplicación utiliza una interfaz gráfica local para evaluar enlaces combinando:
1. **Inteligencia en vivo** (sincronización con la base de datos de URLhaus).
2. **Listas negras locales** de dominios maliciosos conocidos.
3. **Detección heurística** de servicios de alojamiento gratuito combinados con palabras clave sospechosas.
4. **Inteligencia Artificial** mediante un modelo de clasificación *Random Forest* entrenado con un dataset externo.

---

## 🛠️ Tecnologías y Librerías

* **Lenguaje:** Python 3
* **Interfaz Gráfica:** Tkinter
* **Machine Learning:** Scikit-Learn (`RandomForestClassifier`), Pandas
* **Conectividad y Datos:** Requests, Kagglehub
* **Control de Versiones y Difusión:** GitHub y Google Sites

---

## 🚀 Funcionalidades del Prototipo

* 🌐 **Capa 1:** Consulta en tiempo real con el feed global de URLhaus.
* 🛑 **Capa 2:** Verificación mediante lista negra local.
* ⚠️ **Capa 3:** Identificación de patrones de riesgo en hostings gratuitos.
* 🤖 **Capa 4:** Análisis de sintaxis de la URL mediante un modelo de Machine Learning.

---

## 💻 Instalación y Ejecución

### Prerrequisitos
* Tener instalado **Python 3.x** en tu sistema.

### Pasos:

1. **Clona este repositorio:**
   ```bash
   git clone https://github.com/Sylf1/Analizer.git

2. **Accede a la carpeta del proyecto:**
   ```bash
   cd Analizer

3. **Instala las dependencias necesarias:**
   ```bash
   pip install pandas scikit-learn requests kagglehub

4. **Ejecuta la aplicación:**
   ```bash
   python app.py
