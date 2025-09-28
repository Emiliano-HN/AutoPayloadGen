import logging
import sys
from typing import Optional, Dict, List
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text


class SecureMenuManager:
    
    def __init__(self):
        self.console = Console()
        self.setup_logging()
        self.menu_options = self._load_menu_configuration()
        self.max_attempts = 3
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('menu_operations.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _load_menu_configuration(self) -> Dict[str, Dict[str, str]]:
        return {
            "1": {
                "description": "Generar nuevo payload",
                "category": "payload_generation",
                "risk_level": "medium"
            },
            "2": {
                "description": "Lanzar handler manualmente",
                "category": "handler_management", 
                "risk_level": "medium"
            },
            "3": {
                "description": "Iniciar servidor web temporal",
                "category": "server_management",
                "risk_level": "low"
            },
            "4": {
                "description": "Generar código QR de APK",
                "category": "utility",
                "risk_level": "low"
            },
            "5": {
                "description": "Procesar archivo APK",
                "category": "file_processing",
                "risk_level": "high"
            },
            "6": {
                "description": "Salir del programa",
                "category": "system",
                "risk_level": "none"
            }
        }
    
    def validate_option(self, option: str) -> bool:
        try:
            if not option or not isinstance(option, str):
                return False
            
            option_clean = option.strip()
            
            if option_clean not in self.menu_options:
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validando opción: {e}")
            return False
    
    def log_menu_selection(self, option: str):
        try:
            if option in self.menu_options:
                menu_item = self.menu_options[option]
                self.logger.info(f"Opción seleccionada: {option} - {menu_item['description']}")
                self.logger.info(f"Categoría: {menu_item['category']}, Riesgo: {menu_item['risk_level']}")
        except Exception as e:
            self.logger.error(f"Error registrando selección de menú: {e}")
    
    def display_security_warning(self):
        try:
            warning_text = Text()
            warning_text.append("ADVERTENCIA DE SEGURIDAD", style="bold red")
            warning_text.append("\n\nEsta herramienta es solo para:", style="yellow")
            warning_text.append("\n• Pruebas de penetración autorizadas", style="white")
            warning_text.append("\n• Investigación de seguridad ética", style="white")
            warning_text.append("\n• Entornos de laboratorio controlados", style="white")
            warning_text.append("\n\nEl uso no autorizado puede ser ilegal", style="bold red")
            
            warning_panel = Panel(
                warning_text,
                title="[bold red]Aviso Legal[/bold red]",
                border_style="red"
            )
            
            self.console.print(warning_panel)
            self.console.print("")
            
        except Exception as e:
            self.logger.error(f"Error mostrando advertencia: {e}")
            print("ADVERTENCIA: Esta herramienta es solo para uso autorizado")
    
    def create_menu_table(self) -> Table:
        try:
            table = Table(
                title="[bold blue]AutoPayloadGen - Menú Principal[/bold blue]",
                show_header=True,
                header_style="bold magenta"
            )
            
            table.add_column("Opción", style="cyan", no_wrap=True, width=8)
            table.add_column("Descripción", style="green", min_width=30)
            table.add_column("Categoría", style="yellow", width=15)
            table.add_column("Riesgo", style="red", width=10)
            
            for option, details in self.menu_options.items():
                risk_style = self._get_risk_style(details['risk_level'])
                table.add_row(
                    option,
                    details['description'],
                    details['category'].replace('_', ' ').title(),
                    f"[{risk_style}]{details['risk_level'].upper()}[/{risk_style}]"
                )
            
            return table
            
        except Exception as e:
            self.logger.error(f"Error creando tabla de menú: {e}")
            
            fallback_table = Table(title="Menú Principal")
            fallback_table.add_column("Opción", style="cyan")
            fallback_table.add_column("Descripción", style="green")
            
            for option, details in self.menu_options.items():
                fallback_table.add_row(option, details['description'])
            
            return fallback_table
    
    def _get_risk_style(self, risk_level: str) -> str:
        risk_styles = {
            'none': 'green',
            'low': 'green',
            'medium': 'yellow', 
            'high': 'red'
        }
        return risk_styles.get(risk_level, 'white')
    
    def get_secure_user_choice(self) -> Optional[str]:
        try:
            valid_choices = list(self.menu_options.keys())
            
            for attempt in range(self.max_attempts):
                try:
                    choice = Prompt.ask(
                        "[bold yellow]Selecciona una opción[/bold yellow]",
                        choices=valid_choices,
                        show_choices=True
                    )
                    
                    if self.validate_option(choice):
                        return choice.strip()
                    else:
                        self.console.print(f"[red]Opción inválida: {choice}[/red]")
                        continue
                        
                except KeyboardInterrupt:
                    self.console.print("\n[red]Operación cancelada por el usuario[/red]")
                    return None
                except Exception as e:
                    self.logger.error(f"Error obteniendo elección del usuario: {e}")
                    self.console.print(f"[red]Error en la entrada: {e}[/red]")
                    
                    if attempt < self.max_attempts - 1:
                        self.console.print(f"[yellow]Intento {attempt + 1}/{self.max_attempts}[/yellow]")
                    continue
            
            self.console.print(f"[red]Máximo número de intentos alcanzado ({self.max_attempts})[/red]")
            return None
            
        except Exception as e:
            self.logger.error(f"Error crítico obteniendo elección: {e}")
            return None
    
    def confirm_high_risk_operation(self, option: str) -> bool:
        try:
            if option in self.menu_options:
                risk_level = self.menu_options[option]['risk_level']
                
                if risk_level == 'high':
                    self.console.print(f"[red]ADVERTENCIA: Operación de alto riesgo seleccionada[/red]")
                    self.console.print(f"[yellow]{self.menu_options[option]['description']}[/yellow]")
                    
                    confirm = Prompt.ask(
                        "[bold red]¿Confirmar operación de alto riesgo?[/bold red]",
                        choices=["si", "no"],
                        default="no"
                    )
                    
                    confirmed = confirm.lower() == "si"
                    self.logger.warning(f"Operación de alto riesgo {'confirmada' if confirmed else 'cancelada'}: {option}")
                    return confirmed
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error confirmando operación de riesgo: {e}")
            return False
    
    def display_main_menu(self) -> Optional[str]:
        try:
            self.console.clear()
            
            self.display_security_warning()
            
            menu_table = self.create_menu_table()
            self.console.print(menu_table)
            self.console.print("")
            
            choice = self.get_secure_user_choice()
            
            if choice:
                if not self.confirm_high_risk_operation(choice):
                    self.console.print("[yellow]Operación cancelada[/yellow]")
                    return self.display_main_menu()
                
                self.log_menu_selection(choice)
                
                self.console.print(f"[green]Opción seleccionada: {choice} - {self.menu_options[choice]['description']}[/green]")
                self.console.print("")
                
            return choice
            
        except KeyboardInterrupt:
            self.console.print("\n[red]Programa interrumpido por el usuario[/red]")
            self.logger.info("Programa interrumpido por el usuario")
            return None
        except Exception as e:
            self.logger.error(f"Error mostrando menú principal: {e}")
            self.console.print("[red]Error mostrando menú. Usando modo de respaldo.[/red]")
            return self._fallback_menu()
    
    def _fallback_menu(self) -> Optional[str]:
        try:
            print("\n=== MENU PRINCIPAL ===")
            for option, details in self.menu_options.items():
                print(f"{option}. {details['description']}")
            print("=" * 22)
            
            choice = input("Selecciona una opción (1-6): ").strip()
            
            if self.validate_option(choice):
                return choice
            else:
                print("Opción inválida")
                return None
                
        except Exception as e:
            self.logger.error(f"Error en menú de respaldo: {e}")
            return None


menu_manager = SecureMenuManager()


def mostrar_menu_principal():
    return menu_manager.display_main_menu()