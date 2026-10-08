"""
tools/create_screenshot.py — Generator script for terminal screenshot PNGs.
Generates:
  - docs/screenshot_example.png (scan of example.com)
  - docs/screenshot_github.png  (scan of github.com showing Pass, Warning, Fail)
"""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from rich.console import Console
from checker.scanner import scan
from checker.reporter import console_report


def generate_screenshot(url: str, output_path: str, title: str) -> None:
    Path("docs").mkdir(exist_ok=True)

    # Perform scan
    res = scan(url)

    # Format text output
    console = Console(width=88, force_terminal=False, no_color=True, record=True)
    console.print(f"PS C:\\Users\\user\\http-header-checker> python header_checker.py {url}")
    console_report(res, console=console)
    text_output = console.export_text()

    lines = text_output.splitlines()

    try:
        font = ImageFont.truetype("consola.ttf", 15)
    except Exception:
        font = ImageFont.load_default()

    padding = 24
    title_bar_height = 36
    line_height = 20
    width = 820
    height = title_bar_height + (len(lines) * line_height) + (padding * 2)

    # Background window
    img = Image.new("RGBA", (width, height), (30, 30, 30, 255))
    draw = ImageDraw.Draw(img)

    # Title bar
    draw.rectangle([(0, 0), (width, title_bar_height)], fill=(45, 45, 45, 255))

    # Control buttons (red, yellow, green)
    draw.ellipse([(14, 12), (24, 22)], fill=(255, 95, 86, 255))
    draw.ellipse([(32, 12), (42, 22)], fill=(255, 189, 46, 255))
    draw.ellipse([(50, 12), (60, 22)], fill=(39, 201, 63, 255))

    title_font = ImageFont.load_default()
    draw.text((width // 2 - 100, 10), title, fill=(180, 180, 180, 255), font=title_font)

    y = title_bar_height + 15
    for line in lines:
        color = (220, 220, 220, 255)
        if "Score:" in line:
            if "Grade: A" in line or "Grade: B" in line:
                color = (80, 250, 123, 255)
            elif "Grade: C" in line or "Grade: D" in line:
                color = (255, 184, 108, 255)
            else:
                color = (255, 85, 85, 255)
        elif "PASS" in line or "✔" in line:
            color = (80, 250, 123, 255)
        elif "FAIL" in line or "✖" in line:
            color = (255, 120, 120, 255)
        elif "WARNING" in line or "⚠" in line:
            color = (255, 184, 108, 255)
        elif "PS C:" in line or "→ Scanning" in line:
            color = (139, 233, 253, 255)

        draw.text((padding, y), line, fill=color, font=font)
        y += line_height

    img.save(output_path)
    print(f"Generated {output_path}")


if __name__ == "__main__":
    generate_screenshot("https://example.com", "docs/screenshot_example.png", "http-header-checker — example.com")
    generate_screenshot("https://github.com", "docs/screenshot_github.png", "http-header-checker — github.com")
