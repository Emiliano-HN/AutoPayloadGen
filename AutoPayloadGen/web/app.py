from flask import Flask, render_template, send_from_directory, request, abort
from werkzeug.serving import make_server
from threading import Thread, Lock
import socket
import time
import logging
import os
import ipaddress
from pathlib import Path
from typing import Optional, List, Dict


class SecureFlaskDashboard:
    
    def __init__(self):
        self.setup_logging()
        
        self.config = {
            "host": "127.0.0.1",
            "allowed_ports": [8080, 8081, 8082, 9000, 9001],
            "max_duration": 3600,  
            "duration": 1800,  
            "template_dir": "templates",
            "static_dir": "static"
        }
        
        self.data_lock = Lock()
        self.server = None
        self.timer_thread = None
        self.active = False
        
        self.dashboard_data = {
            "payload": "No configurado",
            "lhost": "No configurado", 
            "lport": "No configurado",
            "web_status": "Iniciando",
            "countdown": "30:00",
            "start_time": time.time()
        }
        
        self.remaining_time = self.config["duration"]
        self.app = self._create_secure_flask_app()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('dashboard.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _create_secure_flask_app(self) -> Flask:
        try:
            self._ensure_directories()
            
            app = Flask(
                __name__,
                static_folder=self.config["static_dir"],
                template_folder=self.config["template_dir"]
            )
            
            app.config.update({
                'SECRET_KEY': os.urandom(24),
                'SESSION_COOKIE_HTTPONLY': True,
                'SESSION_COOKIE_SECURE': False,  
                'SESSION_COOKIE_SAMESITE': 'Strict',
                'PERMANENT_SESSION_LIFETIME': 1800,
                'MAX_CONTENT_LENGTH': 1024 * 1024,
            })
            
            self._setup_routes(app)
            self._setup_error_handlers(app)
            
            return app
            
        except Exception as e:
            self.logger.error(f"Error creando aplicación Flask: {e}")
            raise
    
    def _ensure_directories(self):
        try:
            Path(self.config["template_dir"]).mkdir(exist_ok=True)
            Path(self.config["static_dir"]).mkdir(exist_ok=True)
            self.logger.info("Directorios verificados/creados correctamente")
        except Exception as e:
            self.logger.warning(f"No se pudieron crear directorios: {e}")
    
    def _setup_routes(self, app: Flask):
        
        @app.before_request
        def validate_request():
            if not self._is_request_allowed():
                self.logger.warning(f"Solicitud rechazada desde {request.remote_addr}")
                abort(403)
        
        @app.route("/")
        def index():
            return self.render_dashboard()
        
        @app.route("/dashboard")
        def panel():
            return self.render_dashboard()
        
        @app.route("/status")
        def status():
            return self.get_status_json()
        
        @app.route("/static/<path:filename>")
        def serve_static(filename):
            return self.serve_static_file(filename)
    
    def _setup_error_handlers(self, app: Flask):
        
        @app.errorhandler(403)
        def forbidden(error):
            return {"error": "Acceso denegado"}, 403
        
        @app.errorhandler(404)
        def not_found(error):
            return {"error": "Recurso no encontrado"}, 404
        
        @app.errorhandler(413)
        def payload_too_large(error):
            return {"error": "Payload demasiado grande"}, 413
        
        @app.errorhandler(500)
        def internal_error(error):
            self.logger.error(f"Error interno del servidor: {error}")
            return {"error": "Error interno del servidor"}, 500
    
    def _is_request_allowed(self) -> bool:
        try:
            client_ip = request.remote_addr
            
            if not client_ip:
                return False
            
            allowed_ips = ['127.0.0.1', '::1', 'localhost']
            
            try:
                ip_obj = ipaddress.ip_address(client_ip)
                if ip_obj.is_loopback:
                    return True
            except ValueError:
                pass
            
            return client_ip in allowed_ips
            
        except Exception as e:
            self.logger.error(f"Error validando solicitud: {e}")
            return False
    
    def validate_payload_data(self, payload: str, lhost: str, lport: str) -> bool:
        try:
            if not payload or len(payload) > 100:
                return False
            
            allowed_payloads = [
                'android/meterpreter/reverse_tcp',
                'android/meterpreter/reverse_https',
                'windows/meterpreter/reverse_tcp',
                'windows/x64/meterpreter/reverse_https',
                'linux/x64/meterpreter/reverse_tcp'
            ]
            
            if payload not in allowed_payloads:
                return False
            
            try:
                ipaddress.ip_address(lhost)
            except ValueError:
                return False
            
            try:
                port_num = int(lport)
                if not (1 <= port_num <= 65535):
                    return False
            except ValueError:
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validando datos de payload: {e}")
            return False
    
    def update_dashboard_data(self, payload: str = None, lhost: str = None, lport: str = None):
        try:
            with self.data_lock:
                if payload and lhost and lport:
                    if self.validate_payload_data(payload, lhost, lport):
                        self.dashboard_data.update({
                            "payload": payload,
                            "lhost": lhost,
                            "lport": lport
                        })
                        self.logger.info(f"Datos de dashboard actualizados: {payload}")
                    else:
                        self.logger.warning("Datos de payload inválidos rechazados")
                
                mins, secs = divmod(self.remaining_time, 60)
                self.dashboard_data.update({
                    "countdown": f"{mins:02d}:{secs:02d}",
                    "web_status": "Activo" if self.active else "Inactivo"
                })
                
        except Exception as e:
            self.logger.error(f"Error actualizando datos de dashboard: {e}")
    
    def render_dashboard(self):
        try:
            self.update_dashboard_data()
            
            template_path = Path(self.config["template_dir"]) / "dashboard.html"
            
            if not template_path.exists():
                self.logger.warning("Template dashboard.html no encontrado, usando fallback")
                return self._render_fallback_dashboard()
            
            with self.data_lock:
                return render_template(
                    "dashboard.html",
                    **self.dashboard_data
                )
                
        except Exception as e:
            self.logger.error(f"Error renderizando dashboard: {e}")
            return self._render_fallback_dashboard()
    
    def _render_fallback_dashboard(self):
        with self.data_lock:
            data = self.dashboard_data.copy()
        
        return f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Dashboard Seguro - AutoPayloadGen</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #1a1a1a;
                    color: #00ff00;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 800px;
                    margin: 0 auto;
                    background-color: #2a2a2a;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
                }}
                h1 {{
                    text-align: center;
                    margin-bottom: 30px;
                    text-shadow: 0 0 10px #00ff00;
                }}
                .info-grid {{
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                    margin-bottom: 20px;
                }}
                .info-item {{
                    background-color: #333;
                    padding: 15px;
                    border-radius: 5px;
                    border-left: 4px solid #00ff00;
                }}
                .info-label {{
                    font-weight: bold;
                    margin-bottom: 5px;
                }}
                .info-value {{
                    font-size: 1.1em;
                    color: #ffffff;
                }}
                .status-active {{
                    color: #00ff00;
                }}
                .status-inactive {{
                    color: #ff4444;
                }}
                .countdown {{
                    font-size: 1.5em;
                    font-weight: bold;
                    color: #ffaa00;
                }}
            </style>
            <script>
                setInterval(function() {{
                    fetch('/status')
                        .then(response => response.json())
                        .then(data => {{
                            if(data.status === 'success') {{
                                document.getElementById('countdown').textContent = data.data.countdown;
                                document.getElementById('web-status').textContent = data.data.web_status;
                                document.getElementById('web-status').className = 
                                    data.data.web_status === 'Activo' ? 'info-value status-active' : 'info-value status-inactive';
                            }}
                        }})
                        .catch(error => console.log('Error actualizando datos:', error));
                }}, 1000);
            </script>
        </head>
        <body>
            <div class="container">
                <h1>Dashboard de AutoPayloadGen</h1>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Payload:</div>
                        <div class="info-value">{data.get('payload', 'N/A')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">LHOST:</div>
                        <div class="info-value">{data.get('lhost', 'N/A')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">LPORT:</div>
                        <div class="info-value">{data.get('lport', 'N/A')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Estado del Servidor:</div>
                        <div id="web-status" class="info-value {'status-active' if data.get('web_status') == 'Activo' else 'status-inactive'}">{data.get('web_status', 'N/A')}</div>
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">Tiempo Restante:</div>
                    <div id="countdown" class="info-value countdown">{data.get('countdown', 'N/A')}</div>
                </div>
            </div>
        </body>
        </html>
        """
    
    def get_status_json(self):
        try:
            self.update_dashboard_data()
            
            with self.data_lock:
                return {
                    "status": "success",
                    "data": self.dashboard_data.copy()
                }
                
        except Exception as e:
            self.logger.error(f"Error obteniendo status JSON: {e}")
            return {"status": "error", "message": "Error interno"}, 500
    
    def serve_static_file(self, filename: str):
        try:
            safe_filename = os.path.basename(filename)
            
            if '..' in safe_filename or safe_filename.startswith('/'):
                abort(404)
            
            static_path = Path(self.config["static_dir"])
            file_path = static_path / safe_filename
            
            if not file_path.exists() or not file_path.is_file():
                abort(404)
            
            return send_from_directory(self.config["static_dir"], safe_filename)
            
        except Exception as e:
            self.logger.error(f"Error sirviendo archivo estático: {e}")
            abort(404)
    
    def check_port_available(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                result = sock.connect_ex((self.config["host"], port))
                return result != 0
        except Exception:
            return False
    
    def find_available_port(self) -> Optional[int]:
        for port in self.config["allowed_ports"]:
            if self.check_port_available(port):
                return port
        return None
    
    def start_timer_thread(self):
        try:
            def countdown_timer():
                self.logger.info(f"Timer iniciado por {self.config['duration']} segundos")
                
                while self.remaining_time > 0 and self.active:
                    time.sleep(1)
                    self.remaining_time -= 1
                
                if self.active:
                    self.logger.info("Timer expirado, deteniendo servidor")
                    self.stop_server()
            
            if self.timer_thread and self.timer_thread.is_alive():
                self.logger.warning("Timer ya está ejecutándose")
                return
            
            self.timer_thread = Thread(target=countdown_timer, daemon=True)
            self.timer_thread.start()
            
        except Exception as e:
            self.logger.error(f"Error iniciando timer: {e}")
    
    def start_server(self, payload: str = None, lhost: str = None, lport: str = None) -> bool:
        try:
            if payload and lhost and lport:
                self.update_dashboard_data(payload, lhost, lport)
            
            port = self.find_available_port()
            if not port:
                self.logger.error("No hay puertos disponibles")
                print("Error: No hay puertos disponibles en la lista permitida")
                return False
            
            self.server = make_server(
                self.config["host"],
                port,
                self.app,
                threaded=True
            )
            
            self.active = True
            self.start_timer_thread()
            
            print(f"Dashboard iniciado en http://{self.config['host']}:{port}/dashboard")
            print(f"Estado en: http://{self.config['host']}:{port}/status")
            print(f"Tiempo de ejecución: {self.config['duration']} segundos")
            self.logger.info(f"Servidor Flask iniciado en puerto {port}")
            
            self.server.serve_forever()
            
            return True
            
        except KeyboardInterrupt:
            print("\nServidor interrumpido por el usuario")
            self.logger.info("Servidor interrumpido por usuario")
            return False
        except Exception as e:
            self.logger.error(f"Error iniciando servidor: {e}")
            print(f"Error iniciando dashboard: {e}")
            return False
        finally:
            self.stop_server()
    
    def stop_server(self):
        try:
            self.active = False
            
            if self.server:
                self.server.shutdown()
                self.server = None
                print("Servidor Flask detenido")
                self.logger.info("Servidor Flask detenido")
            
        except Exception as e:
            self.logger.error(f"Error deteniendo servidor: {e}")
    
    def start_background_server(self, payload: str = None, lhost: str = None, lport: str = None) -> bool:
        try:
            def background_server():
                self.start_server(payload, lhost, lport)
            
            server_thread = Thread(target=background_server, daemon=True)
            server_thread.start()
            
            time.sleep(2)  
            
            if self.active:
                print("Dashboard ejecutándose en segundo plano")
                return True
            else:
                print("Error iniciando el dashboard en segundo plano")
                return False
                
        except Exception as e:
            self.logger.error(f"Error iniciando servidor background: {e}")
            print(f"Error iniciando servidor en segundo plano: {e}")
            return False


dashboard_manager = SecureFlaskDashboard()


def iniciar_panel_web(payload: str = None, lhost: str = None, lport: str = None):
    return dashboard_manager.start_background_server(payload, lhost, lport)


def actualizar_datos_panel(payload: str, lhost: str, lport: str):
    dashboard_manager.update_dashboard_data(payload, lhost, lport)


def detener_panel_web():
    dashboard_manager.stop_server()


if __name__ == "__main__":
    print("Iniciando SecureFlaskDashboard")
    print("Presiona Ctrl+C para detener el servidor")
    dashboard_manager.start_server()