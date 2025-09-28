import qrcode
import os
import re
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


class SecureQRGenerator:
    
    def __init__(self):
        self.setup_logging()
        self.max_url_length = 2048
        self.max_filename_length = 100
        self.allowed_schemes = ['http', 'https']
        self.output_directory = "qr_codes"
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('qr_generator.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_url(self, url: str) -> bool:
        try:
            if not url or len(url) > self.max_url_length:
                return False
            
            parsed = urlparse(url)
            
            if parsed.scheme not in self.allowed_schemes:
                self.logger.warning(f"Esquema URL no permitido: {parsed.scheme}")
                return False
            
            if not parsed.netloc:
                self.logger.warning("URL sin netloc válido")
                return False
            
            url_pattern = re.compile(
                r'^https?://'
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
                r'localhost|'
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                r'(?::\d+)?'
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            
            return bool(url_pattern.match(url))
            
        except Exception as e:
            self.logger.error(f"Error validando URL: {e}")
            return False
    
    def sanitize_filename(self, filename: str) -> str:
        try:
            dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*', '&', ';', '`', '$']
            sanitized = filename
            
            for char in dangerous_chars:
                sanitized = sanitized.replace(char, '_')
            
            sanitized = re.sub(r'[^\w\-_\.]', '_', sanitized)
            
            sanitized = sanitized[:self.max_filename_length]
            
            if not sanitized.endswith('.png'):
                if '.' in sanitized:
                    sanitized = sanitized.rsplit('.', 1)[0] + '.png'
                else:
                    sanitized = sanitized + '.png'
            
            return sanitized
            
        except Exception as e:
            self.logger.error(f"Error sanitizando nombre de archivo: {e}")
            return "qr_code_secure.png"
    
    def create_output_directory(self) -> bool:
        try:
            path = Path(self.output_directory)
            path.mkdir(parents=True, exist_ok=True, mode=0o755)
            return True
        except Exception as e:
            self.logger.error(f"Error creando directorio de salida: {e}")
            return False
    
    def generate_qr_image(self, url: str, output_path: str) -> bool:
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=4,
            )
            
            qr.add_data(url)
            qr.make(fit=True)
            
            img = qr.make_image(
                fill_color="black", 
                back_color="white"
            )
            
            img.save(output_path)
            
            if not os.path.exists(output_path):
                self.logger.error("Archivo QR no se guardó correctamente")
                return False
            
            file_size = os.path.getsize(output_path)
            if file_size == 0:
                self.logger.error("Archivo QR generado está vacío")
                return False
            
            os.chmod(output_path, 0o644)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error generando imagen QR: {e}")
            return False
    
    def open_qr_securely(self, file_path: str) -> bool:
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"Archivo QR no existe: {file_path}")
                return False
            
            if os.name == 'posix':
                if shutil.which('xdg-open'):
                    result = subprocess.run(
                        ['xdg-open', file_path],
                        capture_output=True,
                        timeout=10,
                        check=False
                    )
                    return result.returncode == 0
                else:
                    self.logger.warning("xdg-open no disponible")
                    return False
            
            elif os.name == 'nt':
                if shutil.which('start'):
                    result = subprocess.run(
                        ['start', '', file_path],
                        shell=True,
                        capture_output=True,
                        timeout=10,
                        check=False
                    )
                    return result.returncode == 0
                else:
                    self.logger.warning("comando start no disponible")
                    return False
            
            return False
            
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeout abriendo archivo QR")
            return False
        except Exception as e:
            self.logger.error(f"Error abriendo archivo QR: {e}")
            return False
    
    def generate_secure_qr(self, url: str, filename: Optional[str] = None) -> bool:
        try:
            if not self.validate_url(url):
                print("Error: URL no válida o no segura")
                self.logger.error(f"URL inválida proporcionada: {url[:100]}")
                return False
            
            if not self.create_output_directory():
                print("Error: No se pudo crear directorio de salida")
                return False
            
            if filename is None:
                filename = "qr_payload.png"
            
            safe_filename = self.sanitize_filename(filename)
            output_path = os.path.join(self.output_directory, safe_filename)
            
            if os.path.exists(output_path):
                backup_path = output_path.replace('.png', '_backup.png')
                try:
                    shutil.move(output_path, backup_path)
                    self.logger.info(f"Archivo existente respaldado: {backup_path}")
                except Exception as e:
                    self.logger.warning(f"No se pudo respaldar archivo existente: {e}")
            
            if not self.generate_qr_image(url, output_path):
                print("Error: No se pudo generar la imagen QR")
                return False
            
            file_size = os.path.getsize(output_path) / 1024
            
            print(f"\nCódigo QR generado exitosamente")
            print(f"Guardado como: {output_path}")
            print(f"Tamaño: {file_size:.1f} KB")
            print(f"URL codificada: {url}")
            
            self.logger.info(f"QR generado exitosamente: {output_path} para URL: {url}")
            
            try_open = input("\n¿Abrir imagen QR? (s/N): ").strip().lower()
            if try_open == 's':
                if self.open_qr_securely(output_path):
                    print("Imagen QR abierta correctamente")
                else:
                    print("No se pudo abrir la imagen automáticamente")
                    print(f"Puedes abrir manualmente: {output_path}")
            
            return True
            
        except KeyboardInterrupt:
            print("\nOperación cancelada por el usuario")
            return False
        except Exception as e:
            self.logger.error(f"Error generando QR seguro: {e}")
            print("Error inesperado generando código QR")
            return False
    
    def validate_and_generate(self, url: str, filename: Optional[str] = None) -> bool:
        try:
            if not url:
                print("Error: URL requerida")
                return False
            
            url_clean = url.strip()
            
            if len(url_clean) == 0:
                print("Error: URL vacía")
                return False
            
            print(f"Validando URL: {url_clean}")
            print("Generando código QR...")
            
            return self.generate_secure_qr(url_clean, filename)
            
        except Exception as e:
            self.logger.error(f"Error en validación y generación: {e}")
            return False


qr_generator = SecureQRGenerator()


def generar_qr(url: str, nombre_archivo: str = "qr_payload.png"):
    return qr_generator.validate_and_generate(url, nombre_archivo)