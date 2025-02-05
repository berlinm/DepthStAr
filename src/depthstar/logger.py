import os
import csv
import json
from datetime import datetime
import inspect
from enum import Enum

class Logger:
    _instance = None

    class LEVEL(Enum):
        DEBUG = 0
        INFO = 1
        WARNING = 2
        ERROR = 3
        CRITICAL = 4
        DETECTION = 5

        def __str__(self):
            return self.name


    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_logger()
        return cls._instance

    def _init_logger(self):
        out_path = os.path.join(os.path.dirname(__file__), "../out")
        os.makedirs(out_path, exist_ok=True)

        # Determine log index
        previous_logs = [int(d) for d in os.listdir(out_path) if d.isnumeric()]
        log_index = max(previous_logs, default=-1) + 1

        # Create log directory
        self.current_out_path = os.path.join(out_path, str(log_index))
        os.makedirs(self.current_out_path, exist_ok=True)

        self.log_file_path = os.path.join(self.current_out_path, "log.txt")
        self.report_file_path = os.path.join(self.current_out_path, "report.csv")
        self.detections_json_path = os.path.join(self.current_out_path, "detections.json")
        self.simple_detections_path = os.path.join(self.current_out_path, "simple_detections.txt")

        # Initialize log files
        self._initialize_log_files()
        self.detections = {}
        self.report_id = 0
        self.current_source = None

    def _initialize_log_files(self):
        with open(self.log_file_path, "w") as log_file:
            log_file.write("\n\nNEW RUN\n" + "-" * 60 + "\n")

        for filepath in [self.report_file_path, self.simple_detections_path, self.detections_json_path]:
            open(filepath, "w").close()

    def detect_source_class_name(self):
        stack = inspect.stack()
        class_names = [frame.frame.f_locals.get("self", None).__class__.__name__ for frame in stack]
        for class_name in class_names:
            if class_name != self.__class__.__name__:
                return class_name

    def log(self, message, level="INFO", should_print=False):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        source = self.detect_source_class_name()
        log_message = f"{timestamp} [{level}] {message}\n"

        with open(self.log_file_path, "a") as log_file:
            if source and source != self.current_source:
                log_file.write(f"\n{source}:\n")
                self.current_source = source
            log_file.write(log_message)

        if should_print:
            print(log_message.strip())

    def log_detection(self, detection):
        """Logs detection details and updates JSON & text logs."""
        binary_name = detection.project.filename
        key = (binary_name, detection.target_function.name, detection.source_function.name)
        
        log_message = (
            f"Project: {binary_name} | State: {detection.state}\n"
            f"Source Function: {detection.source_function.name} @ {detection.source_function.addr}\n"
            f"Target Function: {detection.target_function.name} @ {detection.target_function.addr}\n"
            f"Trace Data: {detection.traces}\n"
        )
        self.log(log_message, level=self.LEVEL.DETECTION, should_print=True)

        # Update detections
        constraints = ""  # Placeholder for path constraints
        if key not in self.detections:
            self.detections[key] = [constraints]
            with open(self.simple_detections_path, "a") as f:
                f.write(json.dumps(list(key)) + "\n")
        else:
            self.detections[key].append(constraints)

        with open(self.detections_json_path, "w") as f:
            json.dump({"length": len(self.detections), "detections": self.detections}, f, indent=4)

    def report(self, detection):
        """Logs detection details into a CSV report."""
        report_line = [
            self.report_id,
            detection.project.filename,
            hex(detection.state.addr),
            detection.function_time,
            detection.binary_time,
            detection.source_function.name,
            detection.target_function.name,
        ]

        with open(self.report_file_path, "a+", newline="") as csvfile:
            reader = csv.reader(csvfile)
            existing_rows = list(reader)
            
            if not any(row and row[2] == report_line[2] and row[5] == report_line[5] and row[6] == report_line[6] for row in existing_rows):
                writer = csv.writer(csvfile)
                writer.writerow(report_line)
                self.report_id += 1

    def debug(self, message, should_print=False):
        self.log(message, level=self.LEVEL.DEBUG, should_print=should_print)

    def info(self, message, should_print=False):
        self.log(message, level=self.LEVEL.INFO, should_print=should_print)

    def warning(self, message, should_print=False):
        self.log(message, level=self.LEVEL.WARNING, should_print=should_print)

    def error(self, message, should_print=False):
        self.log(message, level=self.LEVEL.ERROR, should_print=should_print)

    def critical(self, message, should_print=False):
        self.log(message, level=self.LEVEL.CRITICAL, should_print=should_print)

    def detection(self, message, should_print=False):
        self.log(message, level=self.LEVEL.DETECTION, should_print=should_print)

