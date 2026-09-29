import typer

from .config import load_settings
from .core.engine import IOCEngine
from .detector import detect_ioc
from .output import render_json, render_terminal
from .providers.registry import build_providers
from . import __version__

app = typer.Typer(
    name="prism",
    help="IOC intelligence from multiple threat-intelligence sources.",
)


@app.command("lookup")
def lookup(
    ioc: str = typer.Argument(
        ...,
        help="IP, domain, URL, MD5, SHA1 or SHA256.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output machine-readable JSON.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show provider errors and extra details.",
    ),
):
    """Investigate an IOC."""

    try:
        detected_ioc = detect_ioc(ioc)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))

    settings = load_settings()

    engine = IOCEngine(
        build_providers(settings)
    )

    investigation = engine.investigate(detected_ioc)

    if json_output:
        render_json(investigation)
    else:
        render_terminal(
            investigation,
            verbose=verbose,
        )


@app.command("version")
def version():
    """Show PRISM version."""
    typer.echo(f"PRISM {__version__}")


if __name__ == "__main__":
    app()