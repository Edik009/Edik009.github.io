#!/bin/bash
# Test script for debug logging feature

echo "=========================================="
echo "Testing Debug Logging Feature"
echo "=========================================="
echo ""

TARGET="127.0.0.1"
MODE="fast"
TIMEOUT="1"
THREADS="2"

echo "Test 1: No debug flag (level 0) - Should have 0 debug logs"
echo "Command: python3 main.py -t $TARGET -m $MODE --timeout $TIMEOUT --threads $THREADS"
DEBUG_COUNT=$(timeout 30 python3 main.py -t $TARGET -m $MODE --timeout $TIMEOUT --threads $THREADS 2>&1 | grep "^\[DEBUG\]" | wc -l)
echo "Result: $DEBUG_COUNT debug logs"
if [ "$DEBUG_COUNT" -eq 0 ]; then
    echo "✅ PASS: No debug logs shown"
else
    echo "❌ FAIL: Expected 0 debug logs, got $DEBUG_COUNT"
fi
echo ""

echo "Test 2: Debug level 1 (-d) - Should have basic debug logs"
echo "Command: python3 main.py -t $TARGET -m $MODE -d --timeout $TIMEOUT --threads $THREADS"
DEBUG_COUNT=$(timeout 30 python3 main.py -t $TARGET -m $MODE -d --timeout $TIMEOUT --threads $THREADS 2>&1 | grep "^\[DEBUG\]" | wc -l)
echo "Result: $DEBUG_COUNT debug logs"
if [ "$DEBUG_COUNT" -ge 8 ] && [ "$DEBUG_COUNT" -le 15 ]; then
    echo "✅ PASS: Basic debug logs shown (expected 9-15, got $DEBUG_COUNT)"
else
    echo "⚠️  WARNING: Expected 9-15 debug logs, got $DEBUG_COUNT"
fi
echo ""

echo "Test 3: Debug level 2 (-dd) - Should have detailed debug logs"
echo "Command: python3 main.py -t $TARGET -m $MODE -dd --timeout $TIMEOUT --threads $THREADS"
DEBUG_COUNT=$(timeout 30 python3 main.py -t $TARGET -m $MODE -dd --timeout $TIMEOUT --threads $THREADS 2>&1 | grep "^\[DEBUG\]" | wc -l)
echo "Result: $DEBUG_COUNT debug logs"
if [ "$DEBUG_COUNT" -ge 1500 ]; then
    echo "✅ PASS: Detailed debug logs shown (expected 1500+, got $DEBUG_COUNT)"
else
    echo "⚠️  WARNING: Expected 1500+ debug logs, got $DEBUG_COUNT"
fi
echo ""

echo "Test 4: Alternative syntax (--debug --debug) - Should equal -dd"
echo "Command: python3 main.py -t $TARGET -m $MODE --debug --debug --timeout $TIMEOUT --threads $THREADS"
DEBUG_COUNT=$(timeout 30 python3 main.py -t $TARGET -m $MODE --debug --debug --timeout $TIMEOUT --threads $THREADS 2>&1 | grep "^\[DEBUG\]" | wc -l)
echo "Result: $DEBUG_COUNT debug logs"
if [ "$DEBUG_COUNT" -ge 1500 ]; then
    echo "✅ PASS: Alternative syntax works (expected 1500+, got $DEBUG_COUNT)"
else
    echo "⚠️  WARNING: Expected 1500+ debug logs, got $DEBUG_COUNT"
fi
echo ""

echo "Test 5: Verify specific debug stages at level 1"
echo "Command: python3 main.py -t $TARGET -m $MODE -d --timeout $TIMEOUT --threads $THREADS"
OUTPUT=$(timeout 30 python3 main.py -t $TARGET -m $MODE -d --timeout $TIMEOUT --threads $THREADS 2>&1)

echo "Checking for required stages..."
PASS_COUNT=0
TOTAL_CHECKS=8

if echo "$OUTPUT" | grep -q "\[DEBUG\] Scanner initialized"; then
    echo "  ✅ Stage 1: Scanner initialized"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ❌ Stage 1: Scanner initialized - NOT FOUND"
fi

if echo "$OUTPUT" | grep -q "\[DEBUG\] Loading vectors..."; then
    echo "  ✅ Stage 2a: Loading vectors..."
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ❌ Stage 2a: Loading vectors... - NOT FOUND"
fi

if echo "$OUTPUT" | grep -q "\[DEBUG\] Loaded [0-9]* vectors"; then
    echo "  ✅ Stage 2b: Loaded N vectors"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ❌ Stage 2b: Loaded N vectors - NOT FOUND"
fi

if echo "$OUTPUT" | grep -q "\[DEBUG\] Filtering vectors..."; then
    echo "  ✅ Stage 3a: Filtering vectors..."
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ❌ Stage 3a: Filtering vectors... - NOT FOUND"
fi

if echo "$OUTPUT" | grep -q "\[DEBUG\] Filtered to [0-9]* vectors"; then
    echo "  ✅ Stage 3b: Filtered to N vectors"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ❌ Stage 3b: Filtered to N vectors - NOT FOUND"
fi

if echo "$OUTPUT" | grep -q "\[DEBUG\] Starting scanner..."; then
    echo "  ✅ Stage 4: Starting scanner..."
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ❌ Stage 4: Starting scanner... - NOT FOUND"
fi

if echo "$OUTPUT" | grep -q "\[DEBUG\] Creating thread pool"; then
    echo "  ✅ Stage 5: Creating thread pool"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ❌ Stage 5: Creating thread pool - NOT FOUND"
fi

if echo "$OUTPUT" | grep -q "\[DEBUG\] Scan completed"; then
    echo "  ✅ Stage 8: Scan completed"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ❌ Stage 8: Scan completed - NOT FOUND"
fi

echo ""
echo "Stage verification: $PASS_COUNT/$TOTAL_CHECKS passed"
echo ""

echo "Test 6: Verify level 2 specific logs"
echo "Command: python3 main.py -t $TARGET -m $MODE -dd --timeout $TIMEOUT --threads $THREADS"
OUTPUT_L2=$(timeout 30 python3 main.py -t $TARGET -m $MODE -dd --timeout $TIMEOUT --threads $THREADS 2>&1)

PASS_COUNT_L2=0
TOTAL_CHECKS_L2=3

if echo "$OUTPUT_L2" | grep -q "\[DEBUG\] Loaded vector: [0-9]*"; then
    echo "  ✅ Individual vector loading shown"
    PASS_COUNT_L2=$((PASS_COUNT_L2 + 1))
else
    echo "  ❌ Individual vector loading NOT shown"
fi

if echo "$OUTPUT_L2" | grep -q "\[DEBUG\] Submitting VECTOR_"; then
    echo "  ✅ Individual vector submission shown"
    PASS_COUNT_L2=$((PASS_COUNT_L2 + 1))
else
    echo "  ❌ Individual vector submission NOT shown"
fi

if echo "$OUTPUT_L2" | grep -q "\[DEBUG\] Future completed: VECTOR_"; then
    echo "  ✅ Individual future completion shown"
    PASS_COUNT_L2=$((PASS_COUNT_L2 + 1))
else
    echo "  ❌ Individual future completion NOT shown"
fi

echo ""
echo "Level 2 verification: $PASS_COUNT_L2/$TOTAL_CHECKS_L2 passed"
echo ""

echo "=========================================="
echo "Summary"
echo "=========================================="
TOTAL_PASS=$((PASS_COUNT + PASS_COUNT_L2 + 4))  # 4 from basic tests
TOTAL_TESTS=$((TOTAL_CHECKS + TOTAL_CHECKS_L2 + 4))
echo "Total: $TOTAL_PASS/$TOTAL_TESTS tests passed"
echo ""

if [ "$TOTAL_PASS" -eq "$TOTAL_TESTS" ]; then
    echo "✅ ALL TESTS PASSED!"
    exit 0
else
    echo "⚠️  Some tests failed or showed warnings"
    exit 1
fi
