import os
import platform
import threading
import time
import webbrowser

import typer
from rich.console import Console
from rich.prompt import Prompt

from auditor_ai.client import GeminiClient
from auditor_ai.config import ANALYSIS_TEMPLATE_PROMPT, CHAT_WELCOME_MESSAGE, DEFAULT_MODEL
from auditor_ai.scanner import ejecutar_escaneo_sast
from auditor_ai.utils import escanear_directorio, leer_archivo, mostrar_error_api_key, mostrar_error_general
from auditor_ai.verifier import preguntar_y_ejecutar_verificacion

app = typer.Typer(
    help="Auditor-AI: Asistente CLI de ciberseguridad para auditorías de código inspirado en RAPTOR.",
    no_args_is_help=True
)
console = Console()

def obtener_cliente() -> GeminiClient:
    """Intenta inicializar y retornar el cliente de Gemini. Si falla, sale de la CLI de forma segura."""
    try:
        return GeminiClient()
    except ValueError as e:
        mostrar_error_api_key(str(e))
        raise typer.Exit(code=1)
    except Exception as e:
        mostrar_error_general(str(e))
        raise typer.Exit(code=1)

@app.command("chat")
def chat_comando(
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model", "-m",
        help="Modelo de Gemini a utilizar (ej. gemini-1.5-flash, gemini-1.5-pro)."
    )
):
    """
    Inicia un chat interactivo de seguridad en la terminal con un System Prompt DevSecOps.
    """
    client = obtener_cliente()
    console.print(CHAT_WELCOME_MESSAGE)

    try:
        chat = client.iniciar_chat(model=model)
    except Exception as e:
        mostrar_error_general(f"No se pudo iniciar la sesión de chat: {str(e)}")
        raise typer.Exit(code=1)

    while True:
        try:
            user_input = Prompt.ask("\n[bold cyan]Auditor-AI ➔ [/bold cyan]")
            if user_input.strip().lower() in ("salir", "exit", "quit"):
                console.print("[bold yellow][*] Finalizando sesión de chat de seguridad. ¡Mantente seguro![/bold yellow]")
                break

            if not user_input.strip():
                continue

            console.print("\n[bold green]Gemini ➔ [/bold green]", end="")

            # Ejecutamos el streaming de la respuesta del chat iterando directamente
            stream = chat.send_message_stream(user_input)
            for chunk in stream:
                console.print(chunk.text, end="")
            console.print()  # Nueva línea al finalizar la respuesta

        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold yellow][*] Sesión interrumpida por el usuario. ¡Adiós![/bold yellow]")
            break
        except Exception as e:
            console.print(f"\n[bold red][Error] Ocurrió un fallo en la llamada de IA: {str(e)}[/bold red]")

@app.command("analyze")
def analyze_comando(
    ruta: str = typer.Argument(
        ...,
        help="Ruta al archivo o carpeta de código local a auditar."
    ),
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model", "-m",
        help="Modelo de Gemini a usar."
    )
):
    """
    Analiza un archivo o directorio local en busca de fallos de seguridad y vulnerabilidades lógicas.
    """
    if not os.path.exists(ruta):
        mostrar_error_general(f"La ruta '{ruta}' no existe en el sistema.")
        raise typer.Exit(code=1)

    client = obtener_cliente()

    # Recopilar el contenido a analizar
    if os.path.isdir(ruta):
        console.print(f"[bold blue][*] Escaneando directorio recursivamente:[/bold blue] '{ruta}'...")
        codigo = escanear_directorio(ruta)
    else:
        console.print(f"[bold blue][*] Leyendo archivo individual:[/bold blue] '{ruta}'...")
        codigo = leer_archivo(ruta)

    if not codigo or codigo.strip() == "":
        mostrar_error_general("No se pudo obtener código fuente legible de la ruta especificada.")
        raise typer.Exit(code=1)

    prompt_analisis = ANALYSIS_TEMPLATE_PROMPT.format(code_content=codigo)

    console.print("[bold yellow][*] Enviando contexto a Gemini para auditoría RAPTOR (Etapas A-D)...[/bold yellow]\n")

    try:
        # Iniciamos el stream de la respuesta de Gemini
        stream = client.analizar_codigo_stream(prompt_analisis, model=model)
        for chunk in stream:
            console.print(chunk.text, end="")
        console.print()

    except Exception as e:
        mostrar_error_general(f"Fallo al procesar el análisis con Gemini: {str(e)}")
        raise typer.Exit(code=1)

    # Al finalizar el reporte, se pregunta interactivamente si desea ejecutar verifier.py
    preguntar_y_ejecutar_verificacion(ruta)

@app.command("scan")
def scan_comando(
    ruta: str = typer.Argument(
        ...,
        help="Ruta del proyecto a escanear con herramientas SAST locales."
    ),
    tool: str = typer.Option(
        "all",
        "--tool", "-t",
        help="Herramienta local a correr: 'bandit', 'semgrep', o 'all'."
    ),
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model", "-m",
        help="Modelo de Gemini a usar para interpretar los hallazgos."
    )
):
    """
    Ejecuta herramientas SAST locales (Bandit/Semgrep) y usa Gemini para auditar sus reportes.
    """
    if not os.path.exists(ruta):
        mostrar_error_general(f"La ruta '{ruta}' no existe en el sistema.")
        raise typer.Exit(code=1)

    # 1. Ejecutar análisis estático local
    console.print(f"[bold blue][*] Lanzando herramientas SAST locales en:[/bold blue] '{ruta}'...")
    with console.status("[bold green]Corriendo escáneres estáticos locales...", spinner="dots"):
        reportes_sast = ejecutar_escaneo_sast(ruta, tool=tool)

    # Formatear el informe consolidado para enviarlo a Gemini
    sast_resumen = ""
    for clave, salida in reportes_sast.items():
        sast_resumen += f"=== REPORTE DE {clave.upper()} ===\n{salida}\n\n"

    console.print("[green]✔ Escaneo SAST local finalizado.[/green]")
    console.print("[bold yellow][*] Enviando reportes a Gemini para interpretación y triage RAPTOR...[/bold yellow]\n")

    # 2. Enviar a Gemini
    client = obtener_cliente()
    prompt_sast = (
        "Interpreta la salida de las siguientes herramientas SAST locales sobre el código del proyecto.\n"
        "Identifica los fallos reales de los falsos positivos y genera un reporte en ESPAÑOL "
        "estructurado según la metodología RAPTOR (Etapas A-D):\n\n"
        f"{sast_resumen}"
    )

    try:
        stream = client.analizar_codigo_stream(prompt_sast, model=model)
        for chunk in stream:
            console.print(chunk.text, end="")
        console.print()

    except Exception as e:
        mostrar_error_general(f"Fallo al procesar el reporte SAST con Gemini: {str(e)}")
        raise typer.Exit(code=1)

    # Al finalizar el reporte, se pregunta interactivamente si desea ejecutar verifier.py
    preguntar_y_ejecutar_verificacion(ruta)

@app.command("web")
def web_comando(
    port: int = typer.Option(
        8000,
        "--port", "-p",
        help="Puerto en el que se ejecutará el servidor web local."
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="No abrir el navegador automáticamente al iniciar."
    ),
    model: str = typer.Option(
        DEFAULT_MODEL,
        "--model", "-m",
        help="Modelo de Gemini por defecto para la interfaz web."
    )
):
    """
    Lanza la interfaz web local de Auditor-AI en http://localhost:<port>.
    Detecta automáticamente el sistema operativo y abre el navegador si hay entorno gráfico.
    """
    try:
        import uvicorn

        from auditor_ai.web_server import app as web_app
    except ImportError:
        console.print(
            "[bold red]❌ Dependencias web no instaladas.[/bold red]\n"
            "Instálalas con: [bold cyan]pip install fastapi uvicorn[standard][/bold cyan]"
        )
        raise typer.Exit(code=1)

    # ── Detección de SO ─────────────────────────────────────────────
    sistema = platform.system()        # 'Darwin' | 'Linux' | 'Windows'
    nombre_so = {"Darwin": "macOS", "Linux": "Linux", "Windows": "Windows"}.get(sistema, sistema)

    # Detectar si hay entorno gráfico (útil en servidores Linux sin escritorio)
    def tiene_gui() -> bool:
        if sistema == "Darwin":
            return True   # macOS siempre tiene GUI
        if sistema == "Linux":
            return bool(
                os.environ.get("DISPLAY")
                or os.environ.get("WAYLAND_DISPLAY")
                or os.environ.get("MIR_SOCKET")
            )
        return True

    url = f"http://localhost:{port}"

    console.print()
    console.print("[bold green]🛡️  Auditor-AI — Interfaz Web[/bold green]")
    console.print(f"   [dim]Sistema detectado:[/dim]  [bold]{nombre_so}[/bold]")
    console.print(f"   [dim]Modelo por defecto:[/dim] [bold cyan]{model}[/bold cyan]")
    console.print(f"   [dim]Servidor en:[/dim]        [bold blue]{url}[/bold blue]")

    abrir_navegador = not no_browser

    if abrir_navegador and tiene_gui():
        console.print("   [dim]Navegador:[/dim]          [green]Abriéndose automáticamente...[/green]")
        # Abrir navegador en un hilo secundario tras 1.2 s (dar tiempo al servidor a arrancar)
        def _open():
            time.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()
    elif abrir_navegador and not tiene_gui():
        console.print(f"   [dim]Navegador:[/dim]          [yellow]Sin entorno gráfico — abre manualmente:[/yellow] {url}")
    else:
        console.print("   [dim]Navegador:[/dim]          [dim]Desactivado (--no-browser)[/dim]")

    console.print()
    console.print("[dim]   Pulsa Ctrl+C para detener el servidor.[/dim]\n")

    # ── Lanzar Uvicorn ──────────────────────────────────────────────
    uvicorn.run(
        web_app,
        host="0.0.0.0",
        port=port,
        log_level="warning",     # Sin logs de peticiones para no ensuciar la terminal
        access_log=False,
    )


if __name__ == "__main__":
    app()
