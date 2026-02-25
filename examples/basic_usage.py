"""
Basic Parallax Usage Example

Demonstrates end-to-end workflow:
1. Generate synthetic traffic
2. Run ingestion pipeline
3. Execute detectors
4. Process results
"""

from datetime import datetime, timedelta

from parallax.models import CampaignProfile
from parallax.simulation import TrafficGenerator
from parallax.ingestion import IngestionPipeline
from parallax.detectors import (
    BulkRegistrationDetector,
    VolumeAnomalyDetector,
    AutomationSignatureDetector,
)


def main():
    print("Parallax Basic Usage Example\n")

    # 1. Generate synthetic traffic
    print("Step 1: Generating synthetic traffic...")
    generator = TrafficGenerator(seed=42)

    start_time = datetime.utcnow() - timedelta(days=3)

    # Add organic users
    generator.add_organic_users(
        num_casual=30,
        num_moderate=20,
        num_power=10,
        start_time=start_time
    )

    # Add a distillation campaign
    campaign = CampaignProfile(
        name="example_campaign",
        num_accounts=20,
        post_frequency_mean=15.0,
        post_frequency_std=2.0,
        content_length_mean=180,
        content_length_std=30,
        ip_diversity=0.2,
        device_diversity=0.1,
        time_concentration=0.8,
        token_reuse_rate=0.7
    )
    generator.add_campaign(campaign, start_time)

    # Generate activities
    activities = list(generator.generate_time_window(
        start_time,
        datetime.utcnow(),
        include_registrations=True
    ))

    print(f"  ✓ Generated {len(activities)} activities")

    # 2. Process through ingestion pipeline
    print("\nStep 2: Processing through ingestion pipeline...")
    pipeline = IngestionPipeline()

    # Convert to dict format
    raw_records = [act.model_dump() for act in activities]

    # Enrich
    enriched = list(pipeline.process_batch(raw_records))
    print(f"  ✓ Enriched {len(enriched)} activities")

    # 3. Run detectors
    print("\nStep 3: Running detectors...")

    detectors = [
        BulkRegistrationDetector(),
        VolumeAnomalyDetector(),
        AutomationSignatureDetector(),
    ]

    all_detections = []
    for detector in detectors:
        detections = detector.detect(enriched)
        all_detections.extend(detections)

        if detections:
            print(f"  ⚠ {detector.name}: {len(detections)} detection(s)")
        else:
            print(f"  ✓ {detector.name}: No threats detected")

    # 4. Process results
    print("\nStep 4: Processing results...")

    high_confidence = [d for d in all_detections if d.confidence >= 0.7]

    print(f"\nSummary:")
    print(f"  Total detections: {len(all_detections)}")
    print(f"  High confidence: {len(high_confidence)}")

    if high_confidence:
        print("\nDetailed Results:")
        for detection in high_confidence:
            print(f"\n  {detection.detector_name}")
            print(f"    Severity: {detection.severity.value.upper()}")
            print(f"    Confidence: {detection.confidence:.1%}")
            print(f"    Affected entities: {len(detection.affected_entities)}")
            print(f"    Description: {detection.description}")

    print("\n✅ Example complete!")


if __name__ == "__main__":
    main()
