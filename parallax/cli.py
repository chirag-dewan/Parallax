"""
Parallax CLI

Commands:
- parallax generate: Generate synthetic traffic data
- parallax scan: Run detectors on activity data
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from parallax.models import CampaignProfile, Severity
from parallax.simulation.generator import TrafficGenerator
from parallax.ingestion.pipeline import IngestionPipeline
from parallax.detectors import (
    BulkRegistrationDetector,
    PaymentClusteringDetector,
    LifecycleAnomalyDetector,
    VolumeAnomalyDetector,
    AutomationSignatureDetector,
    TokenReuseDetector,
)

app = typer.Typer(
    name="parallax",
    help="Privacy-Preserving Threat Detection for AI Platforms",
    add_completion=False
)

console = Console()


@app.command()
def generate(
    output: Path = typer.Option(
        "data/synthetic_traffic.jsonl",
        "--output", "-o",
        help="Output file path (JSON Lines format)"
    ),
    num_organic: int = typer.Option(
        100,
        "--organic",
        help="Number of organic users (split: 40% casual, 40% moderate, 20% power)"
    ),
    campaign_size: int = typer.Option(
        50,
        "--campaign-size",
        help="Number of accounts in the distillation campaign"
    ),
    days: int = typer.Option(
        7,
        "--days",
        help="Number of days to simulate"
    ),
    seed: Optional[int] = typer.Option(
        None,
        "--seed",
        help="Random seed for reproducibility"
    ),
) -> None:
    """
    Generate synthetic traffic data with organic users and a distillation campaign.

    Creates realistic user activity patterns including coordinated inauthentic behavior
    for testing and demonstration purposes.
    """
    console.print("\n[bold cyan]Parallax Traffic Generator[/bold cyan]\n")

    # Initialize generator
    generator = TrafficGenerator(seed=seed)

    # Add organic users
    num_casual = int(num_organic * 0.4)
    num_moderate = int(num_organic * 0.4)
    num_power = int(num_organic * 0.2)

    start_time = datetime.utcnow() - timedelta(days=days)
    generator.add_organic_users(num_casual, num_moderate, num_power, start_time)

    console.print(f"✓ Added {num_organic} organic users:")
    console.print(f"  - {num_casual} casual users")
    console.print(f"  - {num_moderate} moderate users")
    console.print(f"  - {num_power} power users")

    # Add distillation campaign
    campaign = CampaignProfile(
        name="demo_campaign",
        num_accounts=campaign_size,
        post_frequency_mean=20.0,
        post_frequency_std=3.0,
        content_length_mean=180,
        content_length_std=40,
        use_shared_ips=True,
        ip_diversity=0.2,
        device_diversity=0.1,
        time_concentration=0.8,
        token_reuse_rate=0.7
    )

    generator.add_campaign(campaign, start_time)
    console.print(f"\n✓ Added distillation campaign with {campaign_size} accounts\n")

    # Generate traffic
    with console.status("[bold green]Generating traffic..."):
        end_time = datetime.utcnow()
        activities = list(generator.generate_time_window(
            start_time,
            end_time,
            include_registrations=True
        ))

    console.print(f"✓ Generated {len(activities)} activities over {days} days\n")

    # Write to file
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, 'w') as f:
        for activity in activities:
            f.write(activity.model_dump_json() + '\n')

    console.print(f"[bold green]✓ Saved to {output}[/bold green]\n")


@app.command()
def scan(
    input_file: Path = typer.Argument(
        ...,
        help="Input file (JSON Lines format)",
        exists=True
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file for detections (JSON)"
    ),
    detectors: Optional[str] = typer.Option(
        None,
        "--detectors", "-d",
        help="Comma-separated list of detector IDs (e.g., 'T0-001,T1-002'). Default: all"
    ),
    min_confidence: float = typer.Option(
        0.7,
        "--min-confidence",
        help="Minimum confidence threshold (0-1)"
    ),
) -> None:
    """
    Scan activity data with Parallax detectors.

    Analyzes user activity for signs of coordinated inauthentic behavior,
    automation, and influence operations.
    """
    console.print("\n[bold cyan]Parallax Threat Scanner[/bold cyan]\n")

    # Load activities
    with console.status("[bold green]Loading activity data..."):
        activities = []
        with open(input_file) as f:
            for line in f:
                data = json.loads(line)
                activities.append(data)

    console.print(f"✓ Loaded {len(activities)} activities\n")

    # Initialize pipeline
    pipeline = IngestionPipeline()

    # Process through ingestion
    with console.status("[bold green]Processing through ingestion pipeline..."):
        enriched = list(pipeline.process_batch(activities))

    console.print(f"✓ Enriched {len(enriched)} activities\n")

    # Initialize detectors
    all_detectors = {
        "T0-001": BulkRegistrationDetector(),
        "T0-002": PaymentClusteringDetector(),
        "T0-005": LifecycleAnomalyDetector(),
        "T1-001": VolumeAnomalyDetector(),
        "T1-002": AutomationSignatureDetector(),
        "T1-003": TokenReuseDetector(),
    }

    # Filter detectors if specified
    if detectors:
        detector_ids = [d.strip() for d in detectors.split(',')]
        active_detectors = {k: v for k, v in all_detectors.items() if k in detector_ids}
    else:
        active_detectors = all_detectors

    console.print(f"Running {len(active_detectors)} detectors:\n")

    # Run detectors
    all_detections = []
    for detector_id, detector in active_detectors.items():
        with console.status(f"[bold yellow]Running {detector.name}..."):
            detections = detector.detect(enriched)
            all_detections.extend(detections)

        if detections:
            console.print(f"  {detector_id}: [bold red]{len(detections)} detection(s)[/bold red]")
        else:
            console.print(f"  {detector_id}: [dim]No detections[/dim]")

    console.print()

    # Filter by confidence
    filtered = [d for d in all_detections if d.confidence >= min_confidence]

    if not filtered:
        console.print("[bold green]✓ No threats detected[/bold green]\n")
        return

    # Display results
    console.print(f"\n[bold red]⚠ {len(filtered)} Detection(s)[/bold red]\n")

    for detection in sorted(filtered, key=lambda d: d.confidence, reverse=True):
        severity_colors = {
            Severity.LOW: "yellow",
            Severity.MEDIUM: "orange1",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red"
        }
        color = severity_colors.get(detection.severity, "white")

        panel = Panel(
            f"[bold]{detection.description}[/bold]\n\n"
            f"Confidence: {detection.confidence:.2%}\n"
            f"Affected Entities: {len(detection.affected_entities)}\n"
            f"Tags: {', '.join(detection.tags)}\n\n"
            f"[dim]Evidence:[/dim]\n{_format_evidence(detection.evidence)}",
            title=f"[{color}]{detection.detector_name}[/{color}]",
            subtitle=f"[{color}]{detection.severity.value.upper()}[/{color}]",
            border_style=color,
            box=box.ROUNDED
        )
        console.print(panel)

    # Save to file if requested
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, 'w') as f:
            json.dump(
                [d.model_dump(mode='json') for d in filtered],
                f,
                indent=2,
                default=str
            )
        console.print(f"\n[bold green]✓ Saved detections to {output}[/bold green]\n")


@app.command()
def version() -> None:
    """Show Parallax version."""
    from parallax import __version__
    console.print(f"\nParallax v{__version__}\n")


def _format_evidence(evidence: dict) -> str:
    """Format evidence dict for display."""
    lines = []
    for key, value in evidence.items():
        if isinstance(value, dict):
            lines.append(f"  {key}:")
            for k, v in value.items():
                lines.append(f"    {k}: {v}")
        elif isinstance(value, list):
            lines.append(f"  {key}: {', '.join(str(v) for v in value[:3])}...")
        else:
            lines.append(f"  {key}: {value}")
    return '\n'.join(lines)


if __name__ == "__main__":
    app()
