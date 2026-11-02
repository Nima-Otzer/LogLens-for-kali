import sys
import csv
from matplotlib.figure import Figure
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from datetime import datetime
from collections import Counter
import re


from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTableWidget, QTableWidgetItem,
    QComboBox, QTabWidget, QTextEdit, QMessageBox, QLineEdit
)
from PySide6.QtCore import Qt


SEVERITIES = [
    "EMERGENCY", "ALERT", "CRITICAL", "ERROR",
    "WARNING", "NOTICE", "INFO", "DEBUG"
]
HIGH_SEVERITY = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR"}


def analyze_log_file(path):
    """Read a timestamp/severity/message log and collect validated events."""
    severity_counts = {level: 0 for level in SEVERITIES}
    events = []
    message_count = Counter()
    high_severity_messages = Counter()
    skipped_count = unknown_count = invalid_count = 0

    with open(path, encoding="utf-8", errors="replace") as file:
        for line_number, line in enumerate(file, start=1):
            parts = line.split()

            if len(parts) < 2:
                skipped_count += 1
                continue

            timestamp = f"{parts[0]} {parts[1]}"

            try:
                datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                invalid_count += 1
                continue

            if len(parts) < 3:
                skipped_count += 1
                continue

            severity = parts[2].upper()
            if severity not in severity_counts:
                unknown_count += 1
                continue

            if len(parts) < 4:
                skipped_count += 1
                continue

            message = " ".join(parts[3:]).strip()
            if not message:
                skipped_count += 1
                continue

            event = {
                "timestamp": timestamp,
                "severity": severity,
                "message": message,
                "line_number": line_number,
            }
            events.append(event)
            severity_counts[severity] += 1
            message_count[message] += 1

            if severity in HIGH_SEVERITY:
                high_severity_messages[message] += 1

    events.sort(key=lambda event: event["timestamp"])

    return {
        "events": events,
        "severity_counts": severity_counts,
        "message_count": message_count,
        "high_severity_messages": high_severity_messages,
        "skipped": skipped_count,
        "unknown": unknown_count,
        "invalid": invalid_count,
    }

def identify_componenets(message):
    message_lower =message.lower()

    components = []

    job_ids = re.findall(r'\bjob\s+(\d+)\b', message_lower)

    for job_id in job_ids:
        components.append(f"job:{job_id}")

    file_paths = re.findall(
        r'(/[a-zA-Z0-9_./-]+)',
        message
    ) 

    for path in file_paths: 
        components.append(f"file:{path}")

    component_keywords = {
        "worker": ["worker"],
        "worker_queue": ["worker queue", "queue connection"],
        "database": ["database", "db connection"],
        "authentication": ["authentication", "login"],
        "backup": ["backup"],
        "network": ["network", "connection"],
        "storage": ["disk", "storage"]
    }

    for component, keywords in component_keywords.items():
        if any(keyword in message_lower for keyword in keywords):
            components.append(components)

    return list(set(components))        

def build_investigation_findings(results, window_seconds=60):
    """
    Detect repeated high-severity messages and high-severity bursts.

    Findings are heuristic indicators. They do not establish a common cause.
    """
    if window_seconds < 1:
        raise ValueError("window_seconds must be at least 1")

    events = sorted(
        results.get("events", []),
        key=lambda event: event["timestamp"]
    )
    findings = []

    def parse_time(event):
        return datetime.strptime(
            event["timestamp"], "%Y-%m-%d %H:%M:%S"
        )

    def format_evidence(matching_events):
        return [
            f"{event['timestamp']} | {event['severity']} | "
            f"{event['message']}"
            for event in matching_events
        ]

    def add_finding(priority, category, title, explanation,
                    signals, matching_events):
        # Deduplicate evidence while preserving chronological order.
        unique = {
            (
                event["timestamp"],
                event["severity"],
                event["message"],
            ): event
            for event in matching_events
        }
        ordered = sorted(unique.values(), key=parse_time)

        if not ordered:
            return

        findings.append({
            "priority": priority,
            "category": category,
            "title": title,
            "explanation": explanation,
            "signals": signals,
            "evidence": format_evidence(ordered),
            "start_time": ordered[0]["timestamp"],
            "end_time": ordered[-1]["timestamp"],
            "_evidence_keys": set(unique),
        })

    repeated_groups = {}
    for event in events:
        if event["severity"] in HIGH_SEVERITY:
            key = event["message"].casefold()
            repeated_groups.setdefault(key, []).append(event)

    for matching in repeated_groups.values():
        if len(matching) < 2:
            continue

        message = matching[0]["message"]
        add_finding(
            priority="HIGH" if len(matching) >= 3 else "MEDIUM",
            category="Repeated failure",
            title=f"Repeated high-severity message: {message}",
            explanation=(
                "The same message was recorded multiple times at a "
                "high severity. This indicates recurring activity, "
                "but does not identify its underlying cause."
            ),
            signals=[
                f"Observed {len(matching)} occurrences across the log."
            ],
            matching_events=matching,
        )

    high_events = [
        event for event in events
        if event["severity"] in HIGH_SEVERITY
    ]
    parsed_high_events = [
        (parse_time(event), event) for event in high_events
    ]

    burst_candidates = []
    left = 0

    for right, (right_time, _) in enumerate(parsed_high_events):
        while (
            right_time - parsed_high_events[left][0]
        ).total_seconds() > window_seconds:
            left += 1

        window_events = [
            event
            for _, event in parsed_high_events[left:right + 1]
        ]

        if len(window_events) >= 3:
            burst_candidates.append(window_events)

    merged_bursts = []
    for candidate in burst_candidates:
        candidate_keys = {
            (event["timestamp"], event["severity"], event["message"])
            for event in candidate
        }

        if not merged_bursts:
            merged_bursts.append(candidate)
            continue

        previous_keys = {
            (event["timestamp"], event["severity"], event["message"])
            for event in merged_bursts[-1]
        }

        if candidate_keys & previous_keys:
            combined = {
                (
                    event["timestamp"],
                    event["severity"],
                    event["message"],
                ): event
                for event in merged_bursts[-1] + candidate
            }
            merged_bursts[-1] = sorted(
                combined.values(), key=parse_time
            )
        else:
            merged_bursts.append(candidate)

    for burst in merged_bursts:
        breakdown = Counter(
            event["severity"] for event in burst
        )
        details = ", ".join(
            f"{severity}: {count}"
            for severity, count in breakdown.items()
        )

        add_finding(
            priority="HIGH" if any(
                event["severity"] in {"EMERGENCY", "ALERT", "CRITICAL"}
                for event in burst
            ) else "MEDIUM",
            category="High-severity burst",
            title=f"{len(burst)} high-severity events within "
                  f"{window_seconds} seconds",
            explanation=(
                "Several high-severity events occurred close together. "
                "This concentration deserves review, but timing alone "
                "does not prove that the events share a cause."
            ),
            signals=[
                f"High-severity event count: {len(burst)}",
                f"Severity breakdown: {details}",
            ],
            matching_events=burst,
        )

    failure_terms = (
        "failed", "failure", "unavailable", "timed out",
        "permission denied", "stopped unexpectedly", "cannot reach",
    )
    recovery_terms = (
        "recovered", "restored", "became available",
        "completed successfully", "succeeded", "connection established",
    )
    ignored_words = {
        "the", "and", "for", "from", "with", "while", "after",
        "before", "service", "application", "system", "failed",
        "failure", "error", "warning", "critical", "successfully",
        "completed", "restored", "available", "unavailable",
    }

    def meaningful_words(message):
        words = {
            word.strip(".,:;()[]{}'\"").casefold()
            for word in message.split()
        }
        return {
            word for word in words
            if len(word) > 2 and word not in ignored_words
        }

    recovery_findings_seen = set()

    for index, failure in enumerate(events):
        failure_message = failure["message"].casefold()
        if not any(term in failure_message for term in failure_terms):
            continue

        failure_time = parse_time(failure)
        failure_words = meaningful_words(failure["message"])

        for later in events[index + 1:]:
            elapsed = (parse_time(later) - failure_time).total_seconds()
            if elapsed > window_seconds:
                break
            if elapsed <= 0:
                continue

            later_message = later["message"].casefold()
            if not any(term in later_message for term in recovery_terms):
                continue

            later_words = meaningful_words(later["message"])
            shared_words = failure_words & later_words

            if not shared_words:
                continue

            pair_key = (
                failure["timestamp"], failure["message"],
                later["timestamp"], later["message"],
            )
            if pair_key in recovery_findings_seen:
                continue
            recovery_findings_seen.add(pair_key)

            add_finding(
                priority="LOW",
                category="Possible recovery",
                title=f"Possible recovery after: {failure['message']}",
                explanation=(
                    "A later message contains recovery-related wording "
                    "and shares terms with the earlier failure. This is "
                    "a possible recovery indicator, not confirmation "
                    "that the underlying issue was resolved."
                ),
                signals=[
                    f"Recovery-like message observed {int(elapsed)} "
                    f"seconds later.",
                    "Shared message terms: "
                    + ", ".join(sorted(shared_words)),
                ],
                matching_events=[failure, later],
            )

    consolidated = []
    for finding in findings:
        overlapping = [
            existing for existing in consolidated
            if existing["_evidence_keys"] & finding["_evidence_keys"]
        ]

        if not overlapping:
            consolidated.append(finding)
            continue

        target = overlapping[0]
        target["_evidence_keys"].update(finding["_evidence_keys"])
        target["signals"] = list(dict.fromkeys(
            target["signals"] + finding["signals"]
        ))

        evidence_by_key = {}
        for evidence_line in target["evidence"] + finding["evidence"]:
            parts = evidence_line.split(" | ", 2)
            if len(parts) == 3:
                evidence_by_key[(parts[0], parts[1], parts[2])] = evidence_line

        ordered_keys = sorted(
            evidence_by_key,
            key=lambda key: key[0]
        )
        target["evidence"] = [
            evidence_by_key[key] for key in ordered_keys
        ]
        target["start_time"] = ordered_keys[0][0]
        target["end_time"] = ordered_keys[-1][0]

        if finding["priority"] == "HIGH":
            target["priority"] = "HIGH"
        if finding["category"] not in target["category"]:
            target["category"] += " + " + finding["category"]

        if finding["title"] not in target["title"]:
            target["title"] += " / " + finding["title"]

        for extra in overlapping[1:]:
            target["_evidence_keys"].update(extra["_evidence_keys"])
            target["signals"] = list(dict.fromkeys(
                target["signals"] + extra["signals"]
            ))
            consolidated.remove(extra)

    for finding in consolidated:
        finding.pop("_evidence_keys", None)

    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    consolidated.sort(
        key=lambda finding: (
            priority_order.get(finding["priority"], 3),
            finding["start_time"],
        )
    )
    return consolidated


class LogLensWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Linux Log Analyzer")
        self.resize(1100, 700)
        self.results = None

        root = QWidget()
        layout = QVBoxLayout(root)

        heading = QLabel("Linux Log Analyzer")
        heading.setStyleSheet("font-size: 28px; font-weight: bold;")

        toolbar = QHBoxLayout()
        self.open_button = QPushButton("Open Log File")
        self.open_button.clicked.connect(self.open_file)

        self.file_label = QLabel("No log file selected")

        self.filter = QComboBox()
        self.filter.addItems(["ALL"] + SEVERITIES)
        self.filter.currentTextChanged.connect(self.populate_events)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search log messages...")
        self.search_box.textChanged.connect(self.populate_events)

        self.export_button = QPushButton("Export CSV")
        self.export_button.clicked.connect(self.export_csv)
        toolbar.addWidget(self.export_button)

        toolbar.addWidget(self.open_button)
        toolbar.addWidget(self.file_label, 1)
        toolbar.addWidget(QLabel("Severity:"))
        toolbar.addWidget(self.filter)
        toolbar.addWidget(QLabel("Search"))
        toolbar.addWidget(self.search_box) 

        self.tabs = QTabWidget()

        self.event_table = QTableWidget(0, 3)
        self.event_table.setHorizontalHeaderLabels(
            ["Timestamp", "Severity", "Message"]
        )
        self.event_table.horizontalHeader().setStretchLastSection(True)
        self.event_table.setAlternatingRowColors(True)
        self.event_table.cellDoubleClicked.connect(self.show_event_details)
        self.tabs.addTab(self.event_table, "Event Timeline")

        summary_widget = QWidget()
        summary_layout = QVBoxLayout(summary_widget)

        self.chart = Figure(figsize=(8, 4))
        self.chart_canvas = FigureCanvasQTAgg(self.chart)
        summary_layout.addWidget(self.chart_canvas)

        self.summary = QTextEdit()
        self.summary.setReadOnly(True)
        summary_layout.addWidget(self.summary)

        self.tabs.addTab(summary_widget, "Analysis Summary")
        self.investigation = QTextEdit()
        self.investigation.setReadOnly(True)
        self.tabs.addTab(self.investigation, "Investigation")
        
        layout.addWidget(heading)
        layout.addLayout(toolbar)
        layout.addWidget(self.tabs)
        self.setCentralWidget(root)

    def export_csv(self):
        if self.results is None:
            QMessageBox.warning(
                self, "No data", "Open a log file first"
            )
            return

        path, _= QFileDialog.getSaveFileName(
            self,
            "Export Filtered Events",
            "loglens_export.csv",
            "CSV files (*.csv)"
        )    

        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "Severity", "Message"])

                for row in range(self.event_table.rowCount()):
                    writer.writerow([
                        self.event_table.item(row, col).text()
                        for col in range(3)
                    ])

        except OSError as error:
            QMessageBox.critical(self, "Export failed", str(error))
            return

        QMessageBox.information(
            self, "Export complete", "Filtered events exported successfully."
        )

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Log File", "",
            "Log files (*.log *.txt);;All files (*)"
        )
        if not path:
            return

        try:
            self.results = analyze_log_file(path)
        except OSError as error:
            QMessageBox.critical(self, "Could not open file", str(error))
            return

        self.filter.setCurrentText("ALL")
        self.search_box.clear()
        
        self.file_label.setText(path)
        self.populate_events()
        self.populate_summary()

    def show_event_details(self, row, column):
        timestamp_item = self.event_table.item(row, 0)
        severity_item = self.event_table.item(row, 1)
        message_item = self.event_table.item(row, 2)

        if not all((timestamp_item, severity_item, message_item)):
            return

        details = (
            f"Timestamp: {timestamp_item.text()}\n"
            f"Severity: {severity_item.text()}\n"
            f"Message: {message_item.text()}"
        )     

        QMessageBox.information(
            self,
            "Log Event Details",
            details
        )

    def populate_events(self):
        if self.results is None:
            return

        events = self.results["events"]
        selected = self.filter.currentText()
        query = self.search_box.text().strip().lower()

        if selected != "ALL":
            events = [event for event in events
                      if event["severity"] == selected]

        if query:
            events = [event for event in events
                      if query in event["message"].lower()]    

        self.event_table.setRowCount(len(events))

        for row, event in enumerate(events):
            for column, key in enumerate(
                ("timestamp", "severity", "message")
            ):
                item = QTableWidgetItem(event[key])
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

                severity = event ["severity"]

                if severity in ("EMERGENCY", "ALERT", "CRITICAL"):
                    item.setBackground(Qt.GlobalColor.darkRed)
                    item.setForeground(Qt.GlobalColor.white)
                elif severity == "ERROR":
                    item.setBackground(Qt.GlobalColor.red)
                    item.setForeground(Qt.GlobalColor.white)    
                elif severity == "WARNING":
                    item.setBackground(Qt.GlobalColor.yellow)
                    item.setForeground(Qt.GlobalColor.black)    

                self.event_table.setItem(row, column, item)

        self.event_table.resizeColumnsToContents()

    def find_correlated_events(self, window_seconds=60):
        """Group nearby events for timeline context; not causal proof."""
        if self.results is None:
            return []

        events = self.results["events"]
        groups = []
        current_group = []
        current_start = None
        previous_time = None

        for event in events:
            timestamp = datetime.strptime(
                event["timestamp"], "%Y-%m-%d %H:%M:%S"
            )

            if not current_group:
                current_group = [event]
                current_start = timestamp
                previous_time = timestamp
                continue

            total_gap = (timestamp - current_start).total_seconds()
            consecutive_gap = (timestamp - previous_time).total_seconds()

            if total_gap <= window_seconds and consecutive_gap <= 30:
                current_group.append(event)
            else:
                if len(current_group) > 1:
                    groups.append(current_group)
                current_group = [event]
                current_start = timestamp

            previous_time = timestamp

        if len(current_group) > 1:
            groups.append(current_group)

        reports = []
        for group in groups:
            message_counts = Counter(
                event["message"] for event in group
            )
            repeated_messages = [
                (message, count)
                for message, count in message_counts.items()
                if count > 1
            ]
            high_events = [
                event for event in group
                if event["severity"] in HIGH_SEVERITY
            ]

            reasons = []
            for message, count in repeated_messages:
                reasons.append(
                    f'Repeated message: "{message}" ({count} occurrences)'
                )

            if len(high_events) >= 2:
                breakdown = Counter(
                    event["severity"] for event in high_events
                )
                details = ", ".join(
                    f"{severity}: {count}"
                    for severity, count in breakdown.items()
                )
                reasons.append(
                    f"High-severity cluster: {len(high_events)} events "
                    f"({details})"
                )

            if not reasons:
                reasons.append(
                    f"Temporal proximity only (within {window_seconds} seconds)"
                )

            reports.append({
                "events": group,
                "reasons": reasons,
            })

        return reports

    def populate_summary(self):
        result = self.results
        lines = ["SEVERITY COUNTS", ""]

        for severity, count in result["severity_counts"].items():
            lines.append(f"{severity}: {count}")

        total = sum(result["severity_counts"].values())
        processed = total + result["skipped"] + result["unknown"] + result["invalid"]

        lines += [
            "",
            "RECURRING HIGH-SEVERITY MESSAGES",
            ""
        ]

        recurring_high = [
            (message, count)
            for message, count in result["high_severity_messages"].items()
            if count > 1
        ]
        lines.extend(
            f"{message}: {count} times" for message, count in recurring_high
        )
        if not recurring_high:
            lines.append("None found.")

        lines += ["", "RECURRING MESSAGES", ""]
        recurring = [
            (message, count)
            for message, count in result["message_count"].items()
            if count > 1
        ]
        lines.extend(
            f"{message}: {count} times" for message, count in recurring
        )
        if not recurring:
            lines.append("None found.")

        lines += [
            "",
            "DATA QUALITY",
            "",
            f"Valid log entries: {total}",
            f"Total entries accounted for: {processed}",
            f"Skipped lines: {result['skipped']}",
            f"Unknown severity entries: {result['unknown']}",
            f"Invalid timestamps: {result['invalid']}",
        ]

        self.summary.setPlainText("\n".join(lines))

        self.chart.clear()
        ax = self.chart.add_subplot(111)

        counts = result["severity_counts"]
        levels = list(counts.keys())
        values = list(counts.values())

        ax.bar(levels, values)
        ax.set_title("Log Entries by Severity")
        ax.set_xlabel("Severity")
        ax.set_ylabel("Count")
        ax.tick_params(axis="x", labelrotation=35)

        self.chart.tight_layout()
        self.chart_canvas.draw()

        correlated = self.find_correlated_events()
        findings = build_investigation_findings(self.results)
        report = []

        for number, finding in enumerate(findings, start=1):
            report.append(
                f"{number}. [{finding['priority']}] "
                f"{finding['category']}"
            )
            report.append(finding["title"])
            report.append(
                f"Period: {finding['start_time']} to {finding['end_time']}"
            )
            report.append(
                finding.get("explanation", "No explanation provided.")
            )

            report.append("Detected signals:")
            for signal in finding.get("signals", []):
                report.append(f"  - {signal}")

            report.append("Evidence:")    

            for evidence in finding.get("evidence", []):
                report.append(f"  - {evidence}")

            report.append("")

        if not findings:
            report.append("No investigation findings detected.")

        self.investigation.setPlainText("\n".join(report))



        lines = ["EVENT CORRELATION (groups within 60 seconds)", ""]

        if correlated:
            for number, report in enumerate(correlated, start=1):
                group = report["events"]
                reasons = ", ".join(report["reasons"])

                lines.append(
                    f"Group {number}: {len(group)} events"
                )                
                lines.append(f"Reason: {reasons}")

                for event in group:
                    lines.append(
                        f" {event['timestamp']} | "
                        f"{event['severity']} | {event['message']}"
                    )

                lines.append("")

            lines.append(
                "Note: These are heuristic groupings, not proof of a common cause."
            )        
        else:
            lines.append(
                "No group of multiple events found within 60 seconds."
            )    

        self.summary.append("\n"+"\n".join(lines))    


app = QApplication(sys.argv)
window = LogLensWindow()
window.show()
sys.exit(app.exec())
