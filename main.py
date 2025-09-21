import requests
import sys
import subprocess
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import time
import signal
import socket

# --- Definición de códigos de color ANSI ---
VERDE = "\033[92m"
BLANCO = "\033[97m"
ROJO = "\033[91m"
AZUL = "\033[94m"
RESET = "\033[0m"

# --- BANNER PRINCIPAL ---
print(f"""{VERDE}


▛▀▘▛▀▘▛▀▖▙ ▌▞▀▖▙ ▌▛▀▖▞▀▖▌     ▌  
▙▄ ▙▄ ▙▄▘▌▌▌▙▄▌▌▌▌▌ ▌▌ ▌▛▀▖▌ ▌▛▀▖
▌  ▌  ▌▚ ▌▝▌▌ ▌▌▝▌▌ ▌▌ ▌▌ ▌▌ ▌▌ ▌
▘  ▀▀▘▘ ▘▘ ▘▘ ▘▘ ▘▀▀ ▝▀ ▘ ▘▝▀▘▀▀ 

                                                                     

{RESET}""")

# --- Funciones (las existentes y las nuevas) ---

def buscar_usuario(username):
    print(f"[*] Buscando el nombre de usuario {AZUL}{username}{RESET}...")
    sitios_encontrados = []
    
    try:
        with open("sitios_usuarios.txt", "r") as f:
            lineas = f.readlines()
    except FileNotFoundError:
        print(f"[!] El archivo '{BLANCO}sitios_usuarios.txt{RESET}' no se encontró.")
        return []

    for linea in lineas:
        nombre_sitio, url_base = linea.strip().split(',')
        url_perfil = url_base.format(username)

        try:
            response = requests.get(url_perfil, timeout=5)
            if response.status_code == 200:
                print(f"{VERDE}[+] Usuario '{username}' ENCONTRADO en {nombre_sitio}{RESET}")
                sitios_encontrados.append(url_perfil)
            else:
                print(f"{ROJO}[-] Usuario '{username}' NO ENCONTRADO en {nombre_sitio}.{RESET}")
        except requests.exceptions.RequestException:
            print(f"[!] {BLANCO}Error al conectar{RESET} con {nombre_sitio} para '{username}'.")
    return sitios_encontrados

def buscar_correo(email):
    print(f"[*] Usando la herramienta {VERDE}Holehe{RESET} para buscar el correo: {email}")
    print("---")

    if "@" not in email or "." not in email:
        print(f"{ROJO}[!] ERROR:{RESET} El formato del correo electrónico es incorrecto.")
        return 

    try:
        proceso = subprocess.run(['holehe', email], capture_output=True, text=True, check=True)
        salida_holehe = proceso.stdout

    except FileNotFoundError:
        print(f"\n{AZUL}[*] Herramienta Holehe no encontrada. Iniciando instalación automática...{RESET}")
        try:
            subprocess.run(['pip', 'install', 'holehe', '--break-system-packages'], check=True)
            print(f"{VERDE}[+] Instalación de Holehe completada. Reejecutando la búsqueda...{RESET}\n")
            proceso = subprocess.run(['holehe', email], capture_output=True, text=True, check=True)
            salida_holehe = proceso.stdout
        except subprocess.CalledProcessError as e:
            print(f"\n{ROJO}[!] ERROR de instalación:{RESET} pip devolvió un error.")
            return

    lineas = salida_holehe.split('\n')
    urls_registradas = []
    for linea in lineas:
        if "Registered" in linea or "Exists" in linea:
            match = re.search(r'https?://[a-zA-Z0-9.-]+', linea)
            if match:
                urls_registradas.append(match.group(0))

    print(f"\n{VERDE}Correo registrado en:{RESET}")
    if urls_registradas:
        for url in urls_registradas:
            print(f"{VERDE}  - {url}{RESET}")
    else:
        print(f"{BLANCO}  - No se encontró registro en sitios populares.{RESET}")
    print(f"\n{BLANCO}--- Salida completa de Holehe ---{RESET}")
    print(salida_holehe)

def track_ip(ip_address):
    print(f"[*] Rastreo de IP en progreso para: {AZUL}{ip_address}{RESET}")
    print("---")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        data = response.json()
        if data['status'] == 'success':
            print(f"{VERDE}[+] Información de IP encontrada:{RESET}")
            print(f"  - País: {data.get('country')}")
            print(f"  - Ciudad: {data.get('city')}")
            print(f"  - Región: {data.get('regionName')}")
            print(f"  - ISP: {data.get('isp')}")
            print(f"  - Organización: {data.get('org')}")
            print(f"  - Latitud/Longitud: {data.get('lat')}, {data.get('lon')}")
        else:
            print(f"{ROJO}[-] No se pudo obtener información para la IP: {ip_address}{RESET}")
            print(f"{BLANCO}Mensaje de error: {data.get('message')}{RESET}")
    except requests.exceptions.RequestException:
        print(f"{ROJO}[!] Error al conectar con el servicio de rastreo de IP.{RESET}")

# --- NUEVA FUNCIÓN: Escanear vulnerabilidad SQL ---
def scan_vulnerability(url):
    print(f"\n[*] Analizando vulnerabilidad de inyección SQL en: {AZUL}{url}{RESET}")
    payloads = ["'", "''", '"', '""']
    sql_errors = ["SQL syntax", "mysql_fetch_array()", "Warning: mysql_query()"]
    try:
        for payload in payloads:
            test_url = f"{url}'" if '?' not in url else f"{url}{payload}"
            print(f"[*] Probando con el payload: {payload}")
            response = requests.get(test_url, timeout=10)
            for error in sql_errors:
                if error in response.text:
                    print(f"\n{ROJO}[!] POSIBLE VULNERABILIDAD DETECTADA:{RESET}")
                    print(f"    - URL vulnerable: {test_url}")
                    print(f"    - Error de base de datos encontrado: {error}")
                    print(f"{VERDE}[+] Recomiendo un análisis más profundo con herramientas especializadas.{RESET}")
                    return
        print(f"\n{VERDE}[+] No se detectaron vulnerabilidades de inyección SQL obvias.{RESET}")
    except requests.exceptions.RequestException as e:
        print(f"{ROJO}[!] Error de conexión: {e}{RESET}")

# --- NUEVAS FUNCIONES: Servidor y túnel Cloudflare ---
cloudflared_pid = None
class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        public_ip = self.headers.get('X-Forwarded-For')
        if public_ip:
            print(f"\n{VERDE}[+] Conexión recibida{RESET}")
            print(f"    - IP del cliente (privada): {AZUL}{client_ip}{RESET}")
            print(f"    - IP del cliente (pública): {AZUL}{public_ip}{RESET}")
        else:
            print(f"\n{VERDE}[+] Conexión recibida{RESET}")
            print(f"    - IP del cliente: {AZUL}{client_ip}{RESET}")
            print(f"    - {ROJO}No se pudo obtener la IP pública.{RESET}")
        try:
            if cloudflared_pid:
                os.kill(cloudflared_pid, signal.SIGINT)
        except NameError:
            pass
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Conectado</h1></body></html>")
        self.server.shutdown()

def run_server(port):
    try:
        server = HTTPServer(('0.0.0.0', port), MyHandler)
        server.serve_forever()
    except Exception as e:
        print(f"{ROJO}[!] ERROR al iniciar el servidor: {e}{RESET}")

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def get_ip_from_link(port):
    global cloudflared_pid
    current_port = port
    while is_port_in_use(current_port):
        print(f"{ROJO}[!] El puerto {current_port} ya está en uso.{RESET}")
        if current_port >= 9995:
            print(f"{ROJO}[!] No se pudo encontrar un puerto disponible en el rango. Saliendo...{RESET}")
            sys.exit(1)
        current_port += 5
        print(f"[*] Intentando con el siguiente puerto disponible: {AZUL}{current_port}{RESET}")
    final_port = current_port
    server_thread = threading.Thread(target=run_server, args=(final_port,))
    server_thread.daemon = True
    server_thread.start()
    print(f"\n[*] Servidor local iniciando en el puerto {final_port}...")
    time.sleep(1)
    print("[*] Servidor local iniciado.")
    try:
        subprocess.run(['cloudflared', '--version'], check=True, capture_output=True)
    except FileNotFoundError:
        print(f"{AZUL}[*] Cloudflared no encontrado. Iniciando instalación automática...{RESET}")
        try:
            subprocess.run(['pkg', 'install', 'cloudflared', '-y'], check=True)
            print(f"{VERDE}[+] Instalación de Cloudflared completada.{RESET}")
        except subprocess.CalledProcessError as e:
            print(f"\n{ROJO}[!] ERROR de instalación:{RESET} pkg devolvió un error.")
            sys.exit(1)
    print(f"\n[*] Levantando un túnel público con Cloudflare...")
    try:
        process = subprocess.Popen(
            ['cloudflared', 'tunnel', '--url', f'http://localhost:{final_port}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        cloudflared_pid = process.pid
        public_url = None
        for line in process.stdout:
            print(line, end='')
            match = re.search(r'https?://[a-zA-Z0-9.-]+\.trycloudflare\.com', line)
            if match:
                public_url = match.group(0)
                print(f"\n{VERDE}[+] ¡Túnel generado con éxito!{RESET}")
                print(f"[*] Enlace de rastreo: {AZUL}{public_url}{RESET}")
                print("\n[*] Esperando la conexión de la víctima...")
                break
        if public_url:
            process.wait()
        else:
            error_output = process.stderr.read()
            print(f"{ROJO}[!] No se pudo obtener el enlace del túnel. Salida de error:\n{error_output}{RESET}")
            process.kill()
    except FileNotFoundError:
        print(f"{ROJO}[!] El comando 'cloudflared' no se encontró.{RESET}")
    except KeyboardInterrupt:
        print(f"\n{ROJO}[!] Interrupción por el usuario. Deteniendo el túnel y el servidor.{RESET}")
    finally:
        if 'process' in locals() and process.poll() is None:
            process.terminate()
            process.wait()
        sys.exit(0)

if __name__ == "__main__":
    try:
        if len(sys.argv) < 3:
            print("Uso: python main.py <opcion> <argumento>")
            print("Ejemplo: python main.py --user anthonydominguez")
            print("Ejemplo: python main.py --email anthonydominguez@gmail.com")
            print("Ejemplo: python main.py --ip 8.8.8.8")
            print("Ejemplo: python main.py --sql http://ejemplo.com/page.php?id=1")
            print("Ejemplo: python main.py --link 8080")
            sys.exit(1)
        
        opcion = sys.argv[1]
        argumento = sys.argv[2]
        
        if opcion == "--user":
            buscar_usuario(argumento)
        elif opcion == "--email":
            buscar_correo(argumento)
        elif opcion == "--ip":
            track_ip(argumento)
        elif opcion == "--sql":
            scan_vulnerability(argumento)
        elif opcion == "--link":
            try:
                port = int(argumento)
                get_ip_from_link(port)
            except ValueError:
                print(f"{ROJO}[!] El puerto debe ser un número válido.{RESET}")
                sys.exit(1)
        else:
            print("Opción inválida. Usa --user, --email, --ip, --sql o --link.")
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{ROJO}[!] User Keyboard Interrupt{RESET}")
        sys.exit(1)

