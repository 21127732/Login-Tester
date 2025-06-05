
# Limbus Wiki Scraper

A structured Python project using Selenium to extract data from the Limbus Company Wiki and optionally take screenshots.

## Setup

1. Install dependencies:
```
pip install -r requirements.txt
```

2. Run the program:
```
python main.py
```

### Options

- `headless_mode`: Set to `True` to run Chrome in the background.
- `scrape_mode`: Set to `True` to take screenshots of each linked page. Will be automatically disabled in headless mode.

Outputs will be saved in `/output/{section}/` folders.
