"""
Script to generate docs/screenshot.png representing a terminal session scanning example.com.
"""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from rich.console import Console
from checker.scanner import scan
from checker.reporter import console_report

# Ensure docs directory exists
Path("docs").mkdir(exist_ok=True)

# Run real scan on example.com
res = scan("https://example.com")

# Format output via Rich text record
console = Console(width=88, force_terminal=False, no_color=True, record=True)
console.print("PS C:\\Users\\user\\http-header-checker> python header_checker.py https://example.com")
console_report(res, console=console)
text_output = console.export_text()

# Render image with Pillow
lines = text_output.splitlines()

# Load default font
try:
    font = ImageFont.truetype("consola.ttf", 15)
except Exception:
    font = ImageFont.load_default()

# Measure text bounds
padding = 24
title_bar_height = 36
line_height = 20
max_width = 800

width = 820
height = title_bar_height + (len(lines) * line_height) + (padding * 2)

# Create background image with subtle shadow / window
img = Image.new("RGBA", (width, height), (30, 30, 30, 255))
draw = ImageDraw.Draw(img)

# Title bar
draw.rectangle([(0, 0), (width, title_bar_height)], fill=(45, 45, 45, 255))

# Window control buttons (red, yellow, green)
draw.ellipse([(14, 12), (24, 22)], fill=(255, 95, 86, 255))
draw.ellipse([(32, 12), (42, 22)], fill=(255, 189, 46, 255))
draw.ellipse([(50, 12), (60, 22)], fill=(39, 201, 63, 255))

# Title text
title_font = ImageFont.load_default()
draw.text((width // 2 - 80, 10), "http-header-checker — terminal", fill=(180, 180, 180, 255), font=title_font)

# Draw terminal text line by line
y = title_bar_height + 15
for line in lines:
    color = (220, 220, 220, 255)
    if "Score:" in line:
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

img.save("docs/screenshot.png")
print("Successfully generated docs/screenshot.png")
