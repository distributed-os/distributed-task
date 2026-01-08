__LOG_COLOR_GREEN='\033[38;5;46m'    # 256 green
__LOG_COLOR_YELLOW='\033[38;5;226m'  # 256 yellow
__LOG_COLOR_RED='\033[38;5;196m'     # 256 red
__LOG_COLOR_RESET='\033[39m'         # reset

pr_info()
{
    echo -e "${__LOG_COLOR_GREEN}[Info] $(date '+%Y-%m-%d %H:%M:%S') - $1${__LOG_COLOR_RESET}"
}

pr_warn()
{
    echo -e "${__LOG_COLOR_YELLOW}[Warn] $(date '+%Y-%m-%d %H:%M:%S') - $1${__LOG_COLOR_RESET}"
}

pr_err()
{
    echo -e "${__LOG_COLOR_RED}[Err] $(date '+%Y-%m-%d %H:%M:%S') - $1${__LOG_COLOR_RESET}"
}

get_version()
{
    local VERSION_FILE="$1"

    # Check if file exists
    if [ ! -f "$VERSION_FILE" ]; then
        return 1
    fi

    local version=$(grep "Version:" "$VERSION_FILE" |  awk '{print $2}')

    # Output the version
    echo "$version"
}
