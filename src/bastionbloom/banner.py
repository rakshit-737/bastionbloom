"""Dependency-free ASCII startup identity, with three terminal-safe designs."""

from enum import StrEnum

from bastionbloom import __version__

WIDTH = 76
TAGLINE = "Local security auditing. Connected risks. Actionable fixes."


class BannerStyle(StrEnum):
    minimal = "minimal"
    aggressive = "aggressive"
    premium = "premium"


MINIMAL = (
    r" ___   _   ___ _____ ___ ___  _  _ ___ _    ___   ___  __  __",
    r"| _ ) /_\ / __|_   _|_ _/ _ \| \| | _ ) |  / _ \ / _ \|  \/  |",
    r"| _ \/ _ \\__ \ | |  | | (_) | .` | _ \ |_| (_) | (_) | |\/| |",
    r"|___/_/ \_\___/ |_| |___\___/|_|\_|___/____\___/ \___/|_|  |_|",
)
AGGRESSIVE = (
    r"   ___  ___   __________________  _  _____  __   ____  ____  __  ___",
    r"  / _ )/ _ | / __/_  __/  _/ __ \/ |/ / _ )/ /  / __ \/ __ \/  |/  /",
    r" / _  / __ |_\ \  / / _/ // /_/ /    / _  / /__/ /_/ / /_/ / /|_/ /",
    r"/____/_/ |_/___/ /_/ /___/\____/_/|_/____/____/\____/\____/_/  /_/",
)
PREMIUM = (
    r"___  ____ ____ ___ _ ____ _  _ ___  _    ____ ____ _  _",
    r"|__] |__| [__   |  | |  | |\ | |__] |    |  | |  | |\/|",
    r"|__] |  | ___]  |  | |__| | \| |__] |___ |__| |__| |  |",
)


def _frame(lines: tuple[str, ...], title: str = "", footer: str = "") -> str:
    top = "+" + (f"--[ {title} ]" if title else "").ljust(WIDTH - 2, "-") + "+"
    rows = [top, "|" + " " * (WIDTH - 2) + "|"]
    glyph_width = max(map(len, lines))
    rows.extend("| " + line.ljust(glyph_width).center(WIDTH - 4) + " |" for line in lines)
    rows.append("|" + " " * (WIDTH - 2) + "|")
    if footer:
        rows.append("| " + footer.center(WIDTH - 4) + " |")
        rows.append("|" + " " * (WIDTH - 2) + "|")
    rows.append("+" + "-" * (WIDTH - 2) + "+")
    return "\n".join(rows)


def render_art(style: BannerStyle | str = BannerStyle.premium) -> str:
    style = BannerStyle(style)
    if style == BannerStyle.minimal:
        return _frame(MINIMAL)
    if style == BannerStyle.aggressive:
        return _frame(AGGRESSIVE, "SECURITY AUDIT // LOCAL CONTROL", ">> SCAN / CORRELATE / HARDEN")
    return _frame(
        PREMIUM, "BB / LOCAL SECURITY INTELLIGENCE",
        "o----o  SECRETS  o----o  DEPLOYMENTS  o----o  WORKFLOWS  o----o",
    )


def render_startup(
    style: BannerStyle | str = BannerStyle.premium,
    version: str = __version__,
    terminal_width: int = WIDTH,
) -> str:
    metadata = f"BastionBloom v{version}\n{TAGLINE}"
    if terminal_width < WIDTH:
        # Narrow terminals get an intact identity instead of wrapped ASCII glyphs.
        return metadata + "\n" + "-" * max(1, terminal_width)
    return render_art(style) + "\n" + metadata + "\n" + "-" * WIDTH
