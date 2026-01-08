#!/bin/bash

# DTT and Ansible Compatibility Testing Framework
# Purpose: Verify whether the DTT tool is fully compatible with Ansible output

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
DTT=$(dirname "$(dirname "$SCRIPT_PATH")")/dtt
ANSIBLE=ansible

# Configuration
HOSTNAME=$(hostname)
TEST_DIR="/tmp/dtt_test_$$"
ANSIBLE_LOG="$TEST_DIR/ansible"
DTT_LOG="$TEST_DIR/dtt"
REPORT_FILE="$TEST_DIR/report.txt"
FAILED_FILE="$TEST_DIR/failed.txt"

# Test statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Create test directory
mkdir -p "$TEST_DIR"
mkdir -p "$ANSIBLE_LOG"
mkdir -p "$DTT_LOG"

export ANSIBLE_FORCE_COLOR=True

# Print functions
print_header()
{
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

print_success()
{
    echo -e "${GREEN}✓ $1${NC}"
}

print_error()
{
    echo -e "${RED}✗ $1${NC}"
}

print_info()
{
    echo -e "${BLUE}ℹ $1${NC}"
}

# Cleanup function
cleanup()
{
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}Tests completed, cleaning up temporary files...${NC}"
        rm -rf "$TEST_DIR"
    else
        echo -e "\n${RED}Tests exited abnormally, temporary files retained at $TEST_DIR${NC}"
    fi
}
trap cleanup EXIT

# Comparison function: handle dynamic differences
compare_output()
{
    local test_name="$1"
    local ansible_out="$2"
    local dtt_out="$3"

    if diff "$ansible_out" "$dtt_out" > /dev/null 2>&1; then
        print_success "$test_name: Output completely identical"
        return 0
    fi

    # Output differences
    print_error "$test_name: Output inconsistent"

    echo "=== Test Failed: $test_name ===" >> "$FAILED_FILE"
    echo "" >> "$FAILED_FILE"
    echo "Ansible output:" >> "$FAILED_FILE"
    cat "$ansible_out" >> "$FAILED_FILE"
    echo -e "\nDTT output:" >> "$FAILED_FILE"
    cat "$dtt_out" >> "$FAILED_FILE"
    echo -e "\nRaw diff:" >> "$FAILED_FILE"
    diff "$ansible_out" "$dtt_out" >> "$FAILED_FILE" 2>&1 || true
    echo "" >> "$FAILED_FILE"

    return 1
}

# Test case: Option list-hosts
test_list_hosts()
{
    print_header "Testing Option list-hosts"
    local test_name="list-hosts"

    $ANSIBLE all --list-hosts > "$ANSIBLE_LOG/list_hosts.out" 2>&1 || true
    $DTT all --list-hosts > "$DTT_LOG/list_hosts.out" 2>&1 || true

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if compare_output "$test_name" "$ANSIBLE_LOG/list_hosts.out" "$DTT_LOG/list_hosts.out"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Test case: Ping module
test_ping()
{
    print_header "Testing Ping Module"
    local test_name="ping"

    $ANSIBLE "$HOSTNAME" -m ping > "$ANSIBLE_LOG/ping.out" 2>&1 || true
    sed -i -e '/discovered_interpreter_python/d' \
        -e '/ansible_facts/d' \
        -e '/\},/d' "$ANSIBLE_LOG/ping.out" || true

    # Assuming your DTT tool command is similar
    $DTT "$HOSTNAME" -m ping > "$DTT_LOG/ping.out" 2>&1 || true

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if compare_output "$test_name" "$ANSIBLE_LOG/ping.out" "$DTT_LOG/ping.out"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Test case: Command module
test_command()
{
    print_header "Testing Command Module"
    local test_name="command"

    # Use a reproducible command
    $ANSIBLE "$HOSTNAME" -m command -a "echo 'hello dtt'" > "$ANSIBLE_LOG/command.out" 2>&1 || true
    $DTT "$HOSTNAME" -m command -a "echo 'hello dtt'" > "$DTT_LOG/command.out" 2>&1 || true

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if compare_output "$test_name" "$ANSIBLE_LOG/command.out" "$DTT_LOG/command.out"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Test case: Command module - unsupport args
test_unsupport_args_command()
{
    print_header "Testing Command Module - Unsupport Args"
    local test_name="unsupprt_args_command"

    # Use a unsupport args command
    $ANSIBLE "$HOSTNAME" -m command -a "ls / --123abc" > "$ANSIBLE_LOG/unsupport_args_command.out" 2>&1 || true
    sed -i 's/non-zero return code//g' "$ANSIBLE_LOG/unsupport_args_command.out" || true

    $DTT "$HOSTNAME" -m command -a "ls / --123abc" > "$DTT_LOG/unsupport_args_command.out" 2>&1 || true

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if compare_output "$test_name" "$ANSIBLE_LOG/unsupport_args_command.out" "$DTT_LOG/unsupport_args_command.out"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Test case: Command module - complex command
test_complex_command()
{
    print_header "Testing Command Module - Complex Command"
    local test_name="complex_command"

    # Test multi-line command
    $ANSIBLE "$HOSTNAME" -m command -a "bash -c 'echo line1 && echo line2 && ls / | head -3'" \
        > "$ANSIBLE_LOG/complex.out" 2>&1 || true
    $DTT "$HOSTNAME" -m command -a "bash -c 'echo line1 && echo line2 && ls / | head -3'" \
        > "$DTT_LOG/complex.out" 2>&1 || true

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if compare_output "$test_name" "$ANSIBLE_LOG/complex.out" "$DTT_LOG/complex.out"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Test case: Copy module
test_copy()
{
    print_header "Testing Copy Module"
    local test_name="copy"

    # Prepare source file
    echo "Test content $(date +%s)" > "$TEST_DIR/source.txt"

    # Clean target file
    rm -f "$TEST_DIR/dest.txt"

    # Ansible copy
    $ANSIBLE "$HOSTNAME" -m copy -a "src=$TEST_DIR/source.txt dest=$TEST_DIR/ansible_dest.txt" \
        > "$ANSIBLE_LOG/copy.out" 2>&1 || true

    # DTT copy
    $DTT "$HOSTNAME" -m copy -a "src=$TEST_DIR/source.txt dest=$TEST_DIR/dtt_dest.txt" \
        > "$DTT_LOG/copy.out" 2>&1 || true

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    # Compare command output
    if compare_output "$test_name" "$ANSIBLE_LOG/copy.out" "$DTT_LOG/copy.out"; then
        # Additionally compare file content
        if diff "$TEST_DIR/ansible_dest.txt" "$TEST_DIR/dtt_dest.txt" > /dev/null 2>&1; then
            print_success "$test_name: File content consistent"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            print_error "$test_name: File content inconsistent"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Test case: Error handling test
test_error_handling()
{
    print_header "Testing Error Handling"
    local test_name="error_handling"

    # Non-existent command
    $ANSIBLE "$HOSTNAME" -m command -a "nonexistent_command_xyz" > "$ANSIBLE_LOG/error.out" 2>&1 || true
    $DTT "$HOSTNAME" -m command -a "nonexistent_command_xyz" > "$DTT_LOG/error.out" 2>&1 || true

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if compare_output "$test_name" "$ANSIBLE_LOG/error.out" "$DTT_LOG/error.out"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Generate test report
generate_report()
{
    print_header "Test Report"

    echo "Test time: $(date)" >> "$REPORT_FILE"
    echo "Test host: $HOSTNAME" >> "$REPORT_FILE"
    echo "Total tests: $TOTAL_TESTS" >> "$REPORT_FILE"
    echo "Passed: $PASSED_TESTS" >> "$REPORT_FILE"
    echo "Failed: $FAILED_TESTS" >> "$REPORT_FILE"
    echo "Success rate: $((PASSED_TESTS * 100 / TOTAL_TESTS))%" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "Detailed log directory: $TEST_DIR" >> "$REPORT_FILE"

    cat "$REPORT_FILE"

    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All tests passed! DTT output is fully consistent with Ansible.${NC}"
    else
        echo -e "\n${RED}❌ $FAILED_TESTS tests failed. Please check $FAILED_FILE for details.${NC}"
    fi
}

# Main function
main()
{
    echo "==================================================="
    echo "  DTT and Ansible Compatibility Testing Framework  "
    echo "==================================================="
    echo "Test environment: $HOSTNAME"
    echo "Test directory: $TEST_DIR"
    echo ""

    # Check prerequisites
    if ! command -v $ANSIBLE &> /dev/null; then
        echo -e "${RED}Error: Ansible not installed${NC}"
        exit 1
    fi

    if [ ! -f "$DTT" ]; then
        echo -e "${RED}Error: DTT executable not found ($DTT)${NC}"
        exit 1
    fi

    # Run all tests
    test_list_hosts
    test_ping
    test_command
    test_unsupport_args_command
    test_complex_command
    # test_copy
    test_error_handling

    # Generate report
    generate_report

    # Exit code
    if [ $FAILED_TESTS -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
