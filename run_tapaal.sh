#!/bin/bash

# run_tapaal.sh - Execute TAPAAL verification for all generated attack trees
#
# This script loops over all models/*.xml and queries/*.q files,
# runs TAPAAL verification (via Docker), captures results and timing,
# and appends results to results.csv in format: model,result,time_sec
#
# Requirements: Docker installed and tapaal/tapaal:3.9.2 image available

set -e  # Exit on any error

# Configuration
DOCKER_IMAGE="tapaal/tapaal:3.9.2"
RESULTS_FILE="results.csv"
TIMEOUT_SECONDS=300  # 5 minutes timeout per verification

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== TAPAAL Diagnosability Verification Runner ==="
echo "Docker image: $DOCKER_IMAGE"
echo "Timeout: $TIMEOUT_SECONDS seconds per verification"
echo "Results file: $RESULTS_FILE"
echo

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    echo "Please install Docker to run TAPAAL verification"
    exit 1
fi

# Check if models and queries directories exist
if [ ! -d "models" ] || [ ! -d "queries" ]; then
    echo -e "${RED}Error: models/ and/or queries/ directories not found${NC}"
    echo "Please run 'python generate_trees.py' first"
    exit 1
fi

# Count available model files
MODEL_COUNT=$(find models -name "tree_*.xml" | wc -l)
QUERY_COUNT=$(find queries -name "tree_*.q" | wc -l)

echo "Found $MODEL_COUNT model files and $QUERY_COUNT query files"

if [ "$MODEL_COUNT" -eq 0 ] || [ "$QUERY_COUNT" -eq 0 ]; then
    echo -e "${RED}Error: No model or query files found${NC}"
    echo "Please run 'python generate_trees.py' first"
    exit 1
fi

# Initialize results file with header
echo "model,result,time_sec" > "$RESULTS_FILE"

# Pull TAPAAL Docker image if not available
echo "Checking TAPAAL Docker image..."
if ! docker image inspect "$DOCKER_IMAGE" &> /dev/null; then
    echo "Pulling TAPAAL Docker image: $DOCKER_IMAGE"
    docker pull "$DOCKER_IMAGE"
fi

# Function to run TAPAAL verification for a single model
run_verification() {
    local model_file="$1"
    local query_file="$2"
    local tree_id="$3"
    
    echo -n "Verifying tree_$tree_id... "
    
    # Start timing
    start_time=$(date +%s.%N)
    
    # Run TAPAAL verification with timeout
    # Mount current directory to /data in container
    local result="TIMEOUT"
    local docker_output
    
    if docker_output=$(timeout "$TIMEOUT_SECONDS" docker run --rm \
        -v "$(pwd):/data" \
        "$DOCKER_IMAGE" \
        verifyta -q /data/"$query_file" /data/"$model_file" 2>&1); then
        
        # Parse TAPAAL output for SAT/UNSAT
        if echo "$docker_output" | grep -q "Query is satisfied"; then
            result="SAT"
        elif echo "$docker_output" | grep -q "Query is NOT satisfied"; then
            result="UNSAT"
        elif echo "$docker_output" | grep -q "satisfied"; then
            result="SAT"
        elif echo "$docker_output" | grep -q "not satisfied\|NOT satisfied"; then
            result="UNSAT"
        else
            result="ERROR"
        fi
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            result="TIMEOUT"
        else
            result="ERROR"
        fi
    fi
    
    # Calculate elapsed time
    end_time=$(date +%s.%N)
    elapsed_time=$(echo "$end_time - $start_time" | bc -l)
    
    # Format elapsed time to 3 decimal places
    elapsed_time_formatted=$(printf "%.3f" "$elapsed_time")
    
    # Append result to CSV
    echo "tree_$tree_id,$result,$elapsed_time_formatted" >> "$RESULTS_FILE"
    
    # Print colored result
    case "$result" in
        "SAT")
            echo -e "${GREEN}SAT${NC} (${elapsed_time_formatted}s)"
            ;;
        "UNSAT")
            echo -e "${YELLOW}UNSAT${NC} (${elapsed_time_formatted}s)"
            ;;
        "TIMEOUT")
            echo -e "${RED}TIMEOUT${NC} (>${TIMEOUT_SECONDS}s)"
            ;;
        "ERROR")
            echo -e "${RED}ERROR${NC} (${elapsed_time_formatted}s)"
            ;;
    esac
    
    # Debug: Save TAPAAL output for analysis (optional)
    if [ ! -d "tapaal_logs" ]; then
        mkdir -p tapaal_logs
    fi
    echo "$docker_output" > "tapaal_logs/tree_${tree_id}.log"
}

# Main verification loop
echo
echo "Starting verification of $MODEL_COUNT trees..."
echo "Progress will be saved to $RESULTS_FILE"
echo

successful=0
failed=0
timeouts=0

# Process each tree in order
for i in $(seq -w 001 100); do
    model_file="models/tree_${i}.xml"
    query_file="queries/tree_${i}.q"
    
    # Check if both files exist
    if [ -f "$model_file" ] && [ -f "$query_file" ]; then
        run_verification "$model_file" "$query_file" "$i"
        
        # Count results
        last_result=$(tail -n 1 "$RESULTS_FILE" | cut -d',' -f2)
        case "$last_result" in
            "SAT"|"UNSAT")
                ((successful++))
                ;;
            "TIMEOUT")
                ((timeouts++))
                ;;
            *)
                ((failed++))
                ;;
        esac
    else
        echo -e "${RED}Missing files for tree_${i}${NC}"
        echo "tree_${i},MISSING,0.000" >> "$RESULTS_FILE"
        ((failed++))
    fi
    
    # Progress update every 10 trees
    if [ $((10#$i % 10)) -eq 0 ]; then
        echo "--- Progress: $i/100 trees completed ---"
    fi
done

# Final summary
echo
echo "=== VERIFICATION COMPLETE ==="
echo "Successful verifications: $successful"
echo "Timeouts: $timeouts"
echo "Errors/Missing: $failed"
echo "Total: $((successful + failed + timeouts))"
echo
echo "Results saved to: $RESULTS_FILE"
echo "TAPAAL logs saved to: tapaal_logs/"
echo
echo "Next step: Run 'python plot_results.py' to generate visualizations"

# Quick results preview
if [ -f "$RESULTS_FILE" ]; then
    echo
    echo "Results preview:"
    echo "SAT results: $(grep -c ",SAT," "$RESULTS_FILE" || echo 0)"
    echo "UNSAT results: $(grep -c ",UNSAT," "$RESULTS_FILE" || echo 0)"
    echo "Timeouts: $(grep -c ",TIMEOUT," "$RESULTS_FILE" || echo 0)"
    echo "Errors: $(grep -c ",ERROR," "$RESULTS_FILE" || echo 0)"
fi
