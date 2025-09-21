#!/bin/bash

# --- Limpia la pantalla ---
clear
# --- BANNER PRINCIPAL ---
echo "========================================"
echo "==                                    =="
echo "==      F E R N A N D O h u b         =="
echo "==      Herramienta OSINT             =="
echo "==                                    =="
echo "========================================"
echo ""
echo "    [Menú Principal]"
echo ""
echo ""

# --- MENU ---
echo "[1] Buscar nombre de usuario"
echo "[2] Buscar correo electrónico"
echo "[3] Rastreo de IP"
echo "[4] Salir"
echo ""

# --- LECTURA DE OPCION ---
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
    echo "Saliendo de la herramienta. ¡Hasta la próxima!"
    exit 0
    
else
    echo "Opción inválida. Por favor, elige 1, 2, 3 o 4."
fi

