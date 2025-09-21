import requests
import sys
import subprocess
import os
import re

# --- Definición de códigos de color ANSI ---
VERDE = "\033[92m"
BLANCO = "\033[97m"
ROJO = "\033[91m"
AZUL = "\033[94m"
RESET = "\033[0m"

# --- BANNER SECUNDARIO (con borde de código) ---
print(f"""{VERDE}


▛▀▘▛▀▘▛▀▖▙ ▌▞▀▖▙ ▌▛▀▖▞▀▖▌     ▌  
▙▄ ▙▄ ▙▄▘▌▌▌▙▄▌▌▌▌▌ ▌▌ ▌▛▀▖▌ ▌▛▀▖
▌  ▌  ▌▚ ▌▝▌▌ ▌▌▝▌▌ ▌▌ ▌▌ ▌▌ ▌▌ ▌
▘  ▀▀▘▘ ▘▘ ▘▘ ▘▘ ▘▀▀ ▝▀ ▘ ▘▝▀▘▀▀ 

                                                                     

{RESET}""")
# --- FIN BANNER ---

# Función para buscar nombres de usuario
def buscar_usuario(username):
    sitios_encontrados = []
    
    try:
        with open("sitios_usuarios.txt", "r") as f:
            lineas = f.readlines()
    except FileNotFoundError:
        print(f"[!] El archivo '{BLANCO}sitios_usuarios.txt{RESET}' no se encontró.")
        return []
        
    for linea in lineas:
        nombre_sitio, url_base = linea.strip().split(',')
        url_perfil = url_base + username
        
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

# Función para buscar correos electrónicos usando Holehe
def buscar_correo(email):
    print(f"[*] Usando la herramienta {VERDE}Holehe{RESET} para buscar el correo: {email}")
    print("---")
    
    # --- Nuevo: Verificación de formato de correo ---
    if "@" not in email or "." not in email:
        print(f"{ROJO}[!] ERROR:{RESET} El formato del correo electrónico es incorrecto. Por favor, ingresa una dirección válida.")
        return # Salimos de la función si el formato es inválido

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
            print(f"\n{ROJO}[!] ERROR de instalación:{RESET} pip devolvió un error. Asegúrate de que tienes 'pip' instalado.")
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
    
# Función para rastrear IPs
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

if __name__ == "__main__":
    try:
        if len(sys.argv) < 3:
            print("Uso: python main.py <opcion> <argumento>")
            print("Ejemplo: python main.py --user anthonydominguez")
            print("Ejemplo: python main.py --email anthonydominguez@gmail.com")
            print("Ejemplo: python main.py --ip 8.8.8.8")
            sys.exit(1)
        
        opcion = sys.argv[1]
        argumento = sys.argv[2]
        
        if opcion == "--user":
            buscar_usuario(argumento)
        elif opcion == "--email":
            buscar_correo(argumento)
        elif opcion == "--ip":
            track_ip(argumento)
        else:
            print("Opción inválida. Usa --user, --email o --ip.")
            sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n{ROJO}[!] User Keyboard Interrupt{RESET}")
        sys.exit(1)
