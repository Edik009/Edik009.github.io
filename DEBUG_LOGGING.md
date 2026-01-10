# Debug Logging System

## Overview
The AASFA Scanner now includes a two-level debug logging system to help diagnose issues during scanning, particularly when the scanner appears to hang or progress stalls.

## Usage

### Level 0 (Default - No Debug)
```bash
python3 main.py -t 192.168.1.44 -m fast
```
No debug logs are shown, only normal scan output.

### Level 1 (Basic Debug)
```bash
python3 main.py -t 192.168.1.44 -m fast -d
# or
python3 main.py -t 192.168.1.44 -m fast --debug
```

Shows basic stage information:
- Scanner initialization
- Vector loading summary
- Vector filtering summary
- Scanner start
- Thread pool creation
- Vector submission summary
- Result processing
- Scan completion

### Level 2 (Detailed Debug)
```bash
python3 main.py -t 192.168.1.44 -m fast -dd
# or
python3 main.py -t 192.168.1.44 -m fast --debug --debug
```

Shows detailed information including:
- All basic debug logs from Level 1
- Each individual vector as it's loaded (1200+ vectors)
- Each vector as it's submitted to the executor
- Each future as it completes with status (CONFIRMED/NOT_FOUND)

## Debug Stages

### Stage 1: Initialization
```
[DEBUG] Scanner initialized
```
Confirms the ScannerEngine has been created successfully.

### Stage 2: Loading Vectors
```
[DEBUG] Loading vectors...
[DEBUG] Loaded vector: 001 (VNC Availability)          # Level 2 only
[DEBUG] Loaded vector: 002 (RDP Availability)          # Level 2 only
...
[DEBUG] Loaded 1200 vectors
```
Shows the vector loading process. Level 2 shows each individual vector.

### Stage 3: Filtering Vectors
```
[DEBUG] Filtering vectors...
[DEBUG] Filtered to 170 vectors (mode: FAST)
```
Shows how many vectors remain after filtering based on scan mode.

### Stage 4: Starting Scanner
```
[DEBUG] Starting scanner...
```
Confirms the scan is about to begin.

### Stage 5: Creating Thread Pool
```
[DEBUG] Creating thread pool (20 workers)
```
Shows the thread pool creation with worker count.

### Stage 6: Submitting Tasks
```
[DEBUG] Submitting 170 vectors to executor
[DEBUG] Submitting VECTOR_001 to executor              # Level 2 only
[DEBUG] Submitting VECTOR_002 to executor              # Level 2 only
...
```
Shows vectors being submitted to the thread pool. Level 2 shows each submission.

### Stage 7: Processing Results
```
[DEBUG] Processing results...
[DEBUG] Future completed: VECTOR_001 → NOT_FOUND       # Level 2 only
[DEBUG] Future completed: VECTOR_002 → CONFIRMED       # Level 2 only
...
```
Shows result processing. Level 2 shows each future completion with status.

### Stage 8: Completion
```
[DEBUG] Scan completed
```
Confirms the scan has finished successfully.

## Troubleshooting with Debug Logs

### Scanner hangs at 0%
Run with `-d` to see which stage is causing the hang:
- If you don't see "Loading vectors..." - issue is in initialization
- If you don't see "Filtered to X vectors" - issue is in vector loading
- If you don't see "Starting scanner..." - issue is in filtering
- If you don't see "Creating thread pool" - issue is before thread pool creation
- If you don't see "Processing results..." - issue is in thread pool setup

### Scanner hangs during progress
Run with `-dd` to see detailed vector processing:
- Look for the last "Submitting VECTOR_XXX" message
- Look for the last "Future completed: VECTOR_XXX" message
- The difference shows which vectors are still pending

### Performance Analysis
Use Level 2 to identify slow vectors:
- Compare submission and completion times
- Look for vectors that take longer to complete
- Identify timeout patterns

## Implementation Details

- Debug logs are printed to stdout with `[DEBUG]` prefix
- Debug level is passed from CLI → ScanConfig → ScannerEngine
- The `debug_log(level, message)` method checks if current debug_level >= requested level
- All debug logging is separate from normal scan output
- Debug logs do not interfere with progress bars or result formatting

## Examples

### Example 1: Basic debugging
```bash
$ python3 main.py -t 192.168.1.44 -m fast -d
[DEBUG] Scanner initialized
[DEBUG] Loading vectors...
[DEBUG] Loaded 1200 vectors
[DEBUG] Filtering vectors...
[DEBUG] Filtered to 170 vectors (mode: FAST)
[DEBUG] Starting scanner...
[DEBUG] Creating thread pool (20 workers)
[DEBUG] Submitting 170 vectors to executor
[DEBUG] Processing results...
[DEBUG] Scan completed
```

### Example 2: Detailed debugging (partial output)
```bash
$ python3 main.py -t 192.168.1.44 -m fast -dd
[DEBUG] Scanner initialized
[DEBUG] Loading vectors...
[DEBUG] Loaded vector: 001 (VNC Availability)
[DEBUG] Loaded vector: 002 (RDP Availability)
... (1200 vectors) ...
[DEBUG] Loaded 1200 vectors
[DEBUG] Filtering vectors...
[DEBUG] Filtered to 170 vectors (mode: FAST)
[DEBUG] Starting scanner...
[DEBUG] Creating thread pool (20 workers)
[DEBUG] Submitting 170 vectors to executor
[DEBUG] Submitting VECTOR_001 to executor
[DEBUG] Submitting VECTOR_002 to executor
... (170 submissions) ...
[DEBUG] Processing results...
[DEBUG] Future completed: VECTOR_001 → NOT_FOUND
[DEBUG] Future completed: VECTOR_003 → NOT_FOUND
[DEBUG] Future completed: VECTOR_002 → CONFIRMED
... (170 completions) ...
[DEBUG] Scan completed
```
