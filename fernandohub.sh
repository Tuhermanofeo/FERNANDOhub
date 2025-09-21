#!/bin/bash

# --- Limpia la pantalla ---
clear

# --- BANNER PRINCIPAL ---
echo ""
echo "▛▀▘▛▀▘▛▀▖▙ ▌▞▀▖▙ ▌▛▀▖▞▀▖▌     ▌"  
echo "▙▄ ▙▄ ▙▄▘▌▌▌▙▄▌▌▌▌▌ ▌▌ ▌▛▀▖▌ ▌▛▀▖"
echo "▌  ▌  ▌▚ ▌▝▌▌ ▌▌▝▌▌ ▌▌ ▌▌ ▌▌ ▌▌ ▌"
echo "▘  ▀▀▘▘ ▘▘ ▘▘ ▘▘ ▘▀▀ ▝▀ ▘ ▘▝▀▘▀▀ "
echo ""

# --- MENU ---
echo "[1] Buscar nombre de usuario"
echo "[2] Buscar correo electrónico"
echo "[3] Rastreo de IP"
echo "[4] Escanear vulnerabilidad web (Inyección SQL)"
echo "[5] Generar enlace para obtener IP"
echo "" # Esta es la línea en blanco que separa las opciones
echo "[99] Salir"
echo ""

# --- LECTURA DE OPCION (separado con un salto de línea) ---
echo ""  
read -p "Elige una opción: " opcion

# --- LOGICA ---
if [ "$opcion" == "1" ]; then
    echo ""
    read -p "Ingresa el nombre de usuario a buscar: " usuario_a_buscar
    echo ""
    python3 main.py --user "$usuario_a_buscar"

elif [ "$opcion" == "2" ]; then
    echo ""
    read -p "Ingresa el correo electrónico a buscar: " correo_a_buscar
    echo ""
    python3 main.py --email "$correo_a_buscar"

elif [ "$opcion" == "3" ]; then
    echo ""
    read -p "Ingresa la dirección IP a rastrear: " ip_a_rastrear
    echo ""
    python3 main.py --ip "$ip_a_rastrear"

elif [ "$opcion" == "4" ]; then
    echo ""
    read -p "Ingresa la URL a escanear: " url_a_escanear
    echo ""
    python3 main.py --sql "$url_a_escanear"

elif [ "$opcion" == "5" ]; then
    echo ""
    read -p "Ingresa el puerto que va a usar (1024-9999): " puerto_a_usar
    echo ""
    python3 main.py --link "$puerto_a_usar"

elif [ "$opcion" == "99" ]; then
    echo "Saliendo de la herramienta. ¡Hasta la próxima!"
    exit 0

else
    echo "Opción inválida. Por favor, elige una opción del menú."
fi
