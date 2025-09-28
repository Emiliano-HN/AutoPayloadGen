import subprocess
import threading
import time
import os
import signal
import sys
import shutil
import logging
import socket
from pathlib import Path
from typing import Optional


class SecurePHPWebServer:
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, serve_dir: str = "web", duration: int = 1800):
        self.setup_logging()
        self.host = self._validate_host(host)
        self.port = self._validate_port(port)
        self.serve_dir = self._validate_directory(serve_dir)
        self.duration = self._validate_duration(duration)
        self.process = None
        self.original_dir = os.getcwd()
        self.shutdown_event = threading.Event()
        self.max_duration = 7200  # 2 horas máximo
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('php_server.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _validate_host(self, host: str) -> str:
        try:
            if host == "0.0.0.0":
                self.logger.warning("Host 0.0.0.0 cambiado a 127.0.0.1 por seguridad")
                return "127.0.0.1"
            
            socket.inet_aton(host)
            
            if host.startswith('127.') or host == 'localhost':
                return host
            else:
                self.logger.warning(f"Host {host} cambiado a 127.0.0.1 por seguridad")
                return "127.0.0.1"
                
        except socket.error:
            self.logger.error(f"Host inválido: {host}, usando 127.0.0.1")
            return "127.0.0.1"
    
    def _validate_port(self, port: int) -> int:
        try:
            if isinstance(port, str):
                port = int(port)
            
            if not (1024 <= port <= 65535):
                self.logger.warning(f"Puerto {port} fuera de rango, usando 8080")
                return 8080
            
            return port
            
        except (ValueError, TypeError):
            self.logger.error(f"Puerto inválido: {port}, usando 8080")
            return 8080
    
    def _validate_directory(self, directory: str) -> str:
        try:
            path = Path(directory).resolve()
            
            if not path.exists():
                self.logger.error(f"Directorio no existe: {directory}")
                path.mkdir(parents=True, exist_ok=True)
                self.logger.info(f"Directorio creado: {directory}")
            
            if not path.is_dir():
                self.logger.error(f"La ruta no es un directorio: {directory}")
                return "."
            
            if not os.access(path, os.R_OK):
                self.logger.error(f"Sin permisos de lectura en: {directory}")
                return "."
            
            return str(path)
            
        except Exception as e:
            self.logger.error(f"Error validando directorio: {e}")
            return "."
    
    def _validate_duration(self, duration: int) -> int:
        try:
            if isinstance(duration, str):
                duration = int(duration)
            
            if duration <= 0:
                self.logger.warning("Duración inválida, usando 30 minutos")
                return 1800
            
            if duration > self.max_duration:
                self.logger.warning(f"Duración limitada a {self.max_duration//60} minutos por seguridad")
                return self.max_duration
            
            return duration
            
        except (ValueError, TypeError):
            self.logger.error(f"Duración inválida: {duration}, usando 30 minutos")
            return 1800
    
    def check_php_availability(self) -> bool:
        try:
            if not shutil.which('php'):
                self.logger.error("PHP no está instalado en el sistema")
                print("Error: PHP no encontrado. Instale PHP para continuar")
                return False
            
            result = subprocess.run(
                ['php', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                php_version = result.stdout.split('\n')[0]
                self.logger.info(f"PHP encontrado: {php_version}")
                return True
            else:
                self.logger.error("Error verificando versión de PHP")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout verificando PHP")
            return False
        except Exception as e:
            self.logger.error(f"Error verificando PHP: {e}")
            return False
    
    def check_port_availability(self) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                result = sock.connect_ex((self.host, self.port))
                
                if result == 0:
                    self.logger.error(f"Puerto {self.port} ya está en uso")
                    print(f"Error: Puerto {self.port} no disponible")
                    return False
                else:
                    return True
                    
        except Exception as e:
            self.logger.error(f"Error verificando puerto: {e}")
            return False
    
    def start_server(self) -> bool:
        try:
            if not self.check_php_availability():
                return False
            
            if not self.check_port_availability():
                return False
            
            original_cwd = os.getcwd()
            
            try:
                os.chdir(self.serve_dir)
                self.logger.info(f"Cambiado a directorio: {self.serve_dir}")
            except Exception as e:
                self.logger.error(f"Error cambiando directorio: {e}")
                return False
            
            print(f"Iniciando servidor PHP en http://{self.host}:{self.port}")
            print(f"Sirviendo directorio: {os.path.abspath(self.serve_dir)}")
            
            try:
                self.process = subprocess.Popen(
                    ["php", "-S", f"{self.host}:{self.port}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid,
                    text=True
                )
                
                time.sleep(2)
                
                if self.process.poll() is not None:
                    stderr_output = self.process.stderr.read() if self.process.stderr else "Sin información"
                    self.logger.error(f"El servidor PHP falló al iniciar: {stderr_output}")
                    print("Error: El servidor PHP no pudo iniciarse")
                    return False
                
                self.logger.info(f"Servidor PHP iniciado con PID: {self.process.pid}")
                print(f"Servidor iniciado exitosamente (PID: {self.process.pid})")
                return True
                
            finally:
                os.chdir(original_cwd)
                
        except Exception as e:
            self.logger.error(f"Error iniciando servidor: {e}")
            print(f"Error inesperado iniciando servidor: {e}")
            return False
    
    def stop_server(self):
        try:
            if self.process and self.process.poll() is None:
                print("\nDeteniendo servidor web...")
                self.logger.info("Iniciando detención del servidor")
                
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                    
                    timeout = 10
                    for _ in range(timeout):
                        if self.process.poll() is not None:
                            break
                        time.sleep(1)
                    else:
                        self.logger.warning("Servidor no respondió a SIGTERM, usando SIGKILL")
                        os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                    
                except ProcessLookupError:
                    self.logger.info("Proceso del servidor ya terminado")
                except Exception as e:
                    self.logger.error(f"Error deteniendo servidor: {e}")
                
                self.process = None
                print("Servidor detenido")
                self.logger.info("Servidor detenido exitosamente")
            
        except Exception as e:
            self.logger.error(f"Error en stop_server: {e}")
    
    def secure_countdown(self):
        try:
            minutes = self.duration // 60
            print(f"Servidor activo por {minutes} minutos")
            print("Presiona Ctrl+C para detener manualmente")
            
            for remaining in range(self.duration, 0, -1):
                if self.shutdown_event.is_set():
                    break
                
                if remaining % 300 == 0 or remaining <= 60:  # Cada 5 min o último minuto
                    mins, secs = divmod(remaining, 60)
                    timeformat = f"{mins:02d}:{secs:02d}"
                    print(f"Tiempo restante: {timeformat}")
                
                time.sleep(1)
            
            if not self.shutdown_event.is_set():
                print("\nTiempo agotado")
                self.logger.info("Servidor detenido por timeout")
            
        except Exception as e:
            self.logger.error(f"Error en countdown: {e}")
    
    def run(self) -> bool:
        try:
            if not self.start_server():
                return False
            
            try:
                self.secure_countdown()
            except KeyboardInterrupt:
                print("\nServidor detenido manualmente por el usuario")
                self.logger.info("Servidor detenido manualmente")
                self.shutdown_event.set()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error ejecutando servidor: {e}")
            print("Error inesperado ejecutando servidor")
            return False
        finally:
            self.stop_server()
    
    def run_in_background(self) -> bool:
        try:
            if not self.start_server():
                return False
            
            def background_timer():
                try:
                    time.sleep(self.duration)
                    self.stop_server()
                    self.logger.info("Servidor detenido por timer en background")
                except Exception as e:
                    self.logger.error(f"Error en timer background: {e}")
            
            timer_thread = threading.Thread(target=background_timer, daemon=True)
            timer_thread.start()
            
            print(f"Servidor ejecutándose en background por {self.duration//60} minutos")
            return True
            
        except Exception as e:
            self.logger.error(f"Error ejecutando servidor en background: {e}")
            return False


def iniciar_php_server_30min():
    try:
        server = SecurePHPWebServer(
            host="127.0.0.1",
            port=8080,
            serve_dir="web",
            duration=1800
        )
        return server.run()
    except Exception as e:
        logging.error(f"Error en iniciar_php_server_30min: {e}")
        print("Error iniciando servidor PHP")
        return False


def iniciar_php_server_background():
    try:
        server = SecurePHPWebServer(
            host="127.0.0.1", 
            port=8080,
            serve_dir="web",
            duration=1800
        )
        return server.run_in_background()
    except Exception as e:
        logging.error(f"Error en iniciar_php_server_background: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "background":
        iniciar_php_server_background()
    else:
        iniciar_php_server_30min()