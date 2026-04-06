#!/usr/bin/env bash
# Download LANL Cyber1 dataset
# Source: https://csr.lanl.gov/data/cyber1/
# License: CC0 (public domain)
#
# NOTE: LANL requires a form submission before granting download access.
#       Visit https://csr.lanl.gov/data/cyber1/ and provide your email
#       and usage description. You will receive download links via email.
#
# Once you have the download links, place the files in data/lanl/:
#
# Total size: ~10.7 GB compressed
#   auth.txt.gz    7.2G  Authentication events
#   proc.txt.gz    2.2G  Process start/stop events
#   flows.txt.gz   1.1G  Network flow data
#   dns.txt.gz     177M  DNS lookups
#   redteam.txt.gz 4.8K  Ground truth compromise labels
#
# After downloading, run the adapter:
#   python lanl_adapter.py \
#     --auth data/lanl/auth.txt.gz \
#     --proc data/lanl/proc.txt.gz \
#     --flows data/lanl/flows.txt.gz \
#     --redteam data/lanl/redteam.txt.gz \
#     --output data/lanl/parallax_events.jsonl \
#     --sample-users 500

set -euo pipefail

DEST="${1:-data/lanl}"

mkdir -p "$DEST"

echo "LANL Cyber1 Dataset Setup"
echo "========================="
echo ""
echo "This dataset requires manual download from LANL."
echo ""
echo "Steps:"
echo "  1. Visit https://csr.lanl.gov/data/cyber1/"
echo "  2. Fill out the form with your email and usage description"
echo "  3. Download the files from the links provided"
echo "  4. Place them in: $DEST/"
echo ""
echo "Required files:"
echo "  auth.txt.gz    (7.2G)  - Authentication events"
echo "  redteam.txt.gz (4.8K)  - Ground truth labels"
echo ""
echo "Optional enrichment files:"
echo "  proc.txt.gz    (2.2G)  - Process events"
echo "  flows.txt.gz   (1.1G)  - Network flows"
echo ""

# Check what we already have
if ls "$DEST"/*.gz 2>/dev/null; then
    echo ""
    echo "Files found in $DEST/:"
    ls -lh "$DEST"/*.gz
else
    echo "No files found in $DEST/ yet."
fi
