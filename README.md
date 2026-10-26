# LogLens for Kali

A local-first Linux log analyzer and GUI continuation of my CLI-based Week 3 Prep project.

## Features

- Browse and filter log events by severity
- Search log messages
- View severity counts and charts
- Identify recurring messages and high-severity events
- Export filtered events to CSV
- Experiment with time-based event correlation and investigation findings

## Requirements

- Python 3
- PySide6
- Matplotlib

## Run locally

Create and activate a virtual environment, then install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Launch the application:

```bash
python "#LogLens-Kali log analyzer.py"
```

LogLens is under development. Its correlation and investigation features are heuristic and do not establish causation.
