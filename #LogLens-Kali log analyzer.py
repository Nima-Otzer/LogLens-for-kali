import sys
import csv
from matplotlib.figure import Figure
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from datetime import datetime, timedelta
from collections import Counter



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
    severity_counts = {level: 0 for level in SEVERITIES}
    events = []
    message_count = Counter()
    high_severity_messages = Counter()
    skipped_count = unknown_count = invalid_count = 0

    with open(path, encoding="utf-8", errors="replace") as file:
        for line in file:
            parts = line.split()

            if len(parts) < 2:
                skipped_count += 1
                continue

            timestamp = parts[0] + " " + parts[1]

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

            message = " ".join(parts[3:])

            severity_counts[severity] += 1
            events.append({
                "timestamp": timestamp,
                "severity": severity,
                "message": message
            })    
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

def build_investigation_findings(results, window_seconds=60):
    """Generate evidence_based finfings from analyzed log events."""

    events = results["events"]
    findings = []

    failure_terms = (
        "failed", "failure", "unavailable", "timed out",
        "premission denied", "stopped unexpectedly",
    )

    recovery_terms = (
        "recovered", "restored", "became available",
        "completed successfully", "succeeded",
    )

    def parse_time(event):
        return datetime.strptime(
            event["timestamp"], "%Y-%m-%d %H:%M:%S"
        )

    for message, count in results["high_severity_messages"].items():
        if count < 2:
            continue

        matching_events = [
            event for event in events
            if event["message"] == message
            and event["severity"] in HIGH_SEVERITY
        ]    

        findings.append({
            "priority": "HIGH",
            "category": "Repeated failure",
            "title": f"Repeated high-severity message: {message}",
            "evidence": [
                f"{event['timestamp']} | {event['severity']} | "
                f"{event['message']}"
                for event in matching_events
            ],
            "explanation": (
                f"This exact high-severity message appered {count} "
                "times in the analyzed log."
            ),

        })

        high_events = [
            event for event in events
            if event["severity"] in HIGH_SEVERITY
        ]

        cluster = []

        for event in high_events:
            if not cluster:
                cluster = [event]
                continue

            elapsed = (
                parse_time(event) - parse_time(cluster[0])
            ).total_seconds()

            if elapsed <= window_seconds:
                cluster.append(event)
            else:
                if len(cluster) >= 3:
                    findings.append({
                        "priority": "HIGH",
                        "category": "Severity burst",
                        "title": (
                            f"{len(cluster)} high-severity events "
                            "within the time window"
                        ),
                        "evidence": [
                            f"{item['timestamp']} | {item['severity']} | "
                            f"{item['message']}"
                            for item in cluster
                        ],
                        "explaination": (
                            "Several high-severity events occured within "
                            f"{window_seconds} seconds. Their timing alone "
                            "does not establish a shared causea."
                        )
                    }) 

                cluster = [event] 

        if len(cluster) >= 3:
            findings.append({
                "priority": "HIGH",
                "category": "Severity burst",
                "title": (
                    f"{len(cluster)} high-severity events "
                    "within the time window"
                ),
                "evidence": [
                    f"{item['timestamp']} | {item['severity']} | "
                    f"{item['message']}"
                    for item in cluster
                ],
                "explaination": (
                    "Several high-severity events occured within "
                    f"{window_seconds} seconds. Their timing alone "
                    "does not establish a shared cause"
                ),
            })

            for index, event in enumerate(events):   
                message = event["message"].lower()

                if not any(term in message for term in failure_terms):
                    continue

                failure_time = parse_time(event)

                for later_event in events[index + 1:]:
                    elapsed = (
                        parse_time(later_event) - failure_time
                    ).total_seconds()

                    if elapsed > 120:
                        break 

                    later_message = later_event["message"].lower()

                    if any(term in later_message for term in recovery_terms):
                        findings.append({
                            "priority": "MEDIUM",
                            "category": "Possible recovery",
                            "title": (
                                f"Possible recovery after: {event['message']}"
                            ),
                            "evidence": [
                                f"{event['timestamp']} | {event['severity']} | "
                                f"{event['message']}",
                                f"{later_event['timestamp']} | "
                                f"{later_event['severity']} | "
                                f"{later_event['message']}",
                            ],
                            "explanation": (
                                f"A possible recovery message appeared "
                                f"{int(elapsed)} seconds after the failure. "
                                "This timing does not prove the failure was resolved."
                            ),
                        })
                        break 
                    
                findings.sort(
                    key=lambda finding: (
                        {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(
                            finding["priority"], 3
                        ),
                        finding["title"]
                    )
                )    

                return findings


class LogLensWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LogLens — Linux Log Analyzer")
        self.resize(1100, 700)
        self.results = None

        root = QWidget()
        layout = QVBoxLayout(root)

        heading = QLabel("LogLens")
        heading.setStyleSheet("font-size: 28px; font-weight: bold;")

        toolbar = QHBoxLayout()
        self.open_button = QPushButton("Open Log File")
        self.open_button.clicked.connect(self.open_file)

        self.file_label = QLabel("No log file selected")

        self.filter = QComboBox()
        self.filter.addItems(["ALL"] + SEVERITIES)
        self.filter.currentTextChanged.connect(self.populate_events)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("search log messages...")
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
        self.tabs.addTab(self.investigation, "investigation")
        
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
            self, "Export complete", "Filetered events exported successfully."
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

    def find_correlated_events(self, window_second=60):
        if self.results is None:
            return[]

        events = self.results["events"]
        groups = []
        current_group = []

        for event in events:
            timestamp = datetime.strptime(
                event["timestamp"], "%Y-%m-%d %H:%M:%S"
            )    

            timed_event = {**event, "_parsed_time": timestamp}

            if not current_group:
                current_group = [timed_event]
                continue

            group_start_time = current_group[0]["_parsed_time"]
            gap = (timestamp - group_start_time).total_seconds()

            previous_time = current_group[-1]["_parsed_time"]
            gap_from_previous = (timestamp - previous_time).total_seconds()

            if gap <= window_second and gap_from_previous <= 30:
                current_group.append(timed_event)
            else:
                if len(current_group) > 1:
                    groups.append(current_group)

                current_group = [timed_event]

        if len(current_group) > 1:
            groups.append(current_group)

        reports = []

        for group in groups:
            messages = Counter(
               event["message"] for event in group
            )

            high_severity_repeats = {
                message: count
                for message, count in self.results["high_severity_messages"].items()
                if count > 1
            }

            high_severity_count = sum(
               event["severity"] in HIGH_SEVERITY
               for event in group
            )

            reasons = []

            repeated_messages = {
                message: count
                for message, count in messages.items()
                if count > 1
            }

            for message, count in repeated_messages.items():
                reasons.append(
                    f'Repeated message: "{message}"'
                    f'({count} occurrences)'
                )

            high_severity_events = [
                event for event in group
                if event["severity"] in HIGH_SEVERITY
            ]    

            if len(high_severity_events) >= 2:
                severity_counts = Counter(
                    event["severity"]
                    for event in high_severity_events
                )
                breakdown = ", ".join(
                    f"{severity}: {count}"
                    for severity, count in severity_counts.items()
                )

                reasons.append(
                    f"High-severity cluster: "
                    f"{len(high_severity_events)} events ({breakdown})"
                )

            if not reasons:
                reasons.append(
                    "Temporal proximity only "
                    f"(within {window_second} seconds)"
                )

            clean_events = [
                {
                    key: value
                    for key, value in event.items()
                    if key != "_parsed_time"
                }
                for event in group
            ]

            reports.append({
                "events": clean_events,
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
            report.append(finding['title'])
            report.append(
                finding.get("explanation", "No explanation provided.")
            )
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

test_results = analyze_log_file("/home/manjusri/Documents/Terra/Loglens/loglens_sample_new.log")
test_findings = build_investigation_findings(test_results)

print("\nINVESTIGATION ENGINE TEST")
print(f"Total findings: {len(test_findings)}")

for finding in test_findings:
    print(f"\n[{finding['priority']}]{finding['category']}")
    print(finding["title"])
    print(finding.get("explanation", "No explanation provided."))

    for evidence in finding.get("evidence", []):
        print(f" - {evidence}")

app = QApplication(sys.argv)
window = LogLensWindow()
window.show()
sys.exit(app.exec())