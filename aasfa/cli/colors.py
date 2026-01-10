"""Color definitions for beautiful terminal output"""

class Colors:
    """ANSI color codes"""

    # Reset
    RESET = '\033[0m'
    BOLD = '\033[1m'

    # Colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'

    # Background colors
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'
    BG_BLUE = '\033[104m'


def colorize(text: str, color: str) -> str:
    """Apply color to text"""
    return f"{color}{text}{Colors.RESET}"


def red(text: str) -> str:
    return colorize(text, Colors.RED)


def green(text: str) -> str:
    return colorize(text, Colors.GREEN)


def yellow(text: str) -> str:
    return colorize(text, Colors.YELLOW)


def blue(text: str) -> str:
    return colorize(text, Colors.BLUE)


def cyan(text: str) -> str:
    return colorize(text, Colors.CYAN)


def bold(text: str) -> str:
    return colorize(text, Colors.BOLD)


def use_colors() -> bool:
    """Check if terminal supports colors"""
    import sys
    return sys.stdout.isatty()
