import os
import csv
import json
from datetime import datetime
import inspect
from enum import Enum
import z3

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


    def __new__(cls, out_directory=None, debug_z3=False):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls.is_initialized = False

        if not cls.is_initialized and out_directory:
            cls._instance._init_logger(out_directory, debug_z3)
        
        return cls._instance

    def _init_logger(self, out_path, debug_z3):
        if not out_path:
            out_path = DEFAULT_OUTPUT_DIRECTORY
        os.makedirs(out_path, exist_ok=True)
        
        # Determine log index
        previous_logs = [int(d) for d in os.listdir(out_path) if d.isnumeric()]
        log_index = max(previous_logs, default=-1) + 1

        # Create log directory
        self.current_out_path = os.path.join(out_path, str(log_index))
        os.makedirs(self.current_out_path, exist_ok=True)

        
        if debug_z3:
            self.z3_debug_file = os.path.join(self.current_out_path, "z3.log")
            z3.Z3_open_log("z3.log")
            z3.set_param('verbose', 10)

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
        
        # Make sure all the log files exist
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
        
        # Prepare the log and write it to the standard log file
        log_message = (
            f"Project: {binary_name} | State: {detection.state}\n"
            f"Source Function: {detection.source_function.name} @ {detection.source_function.addr}\n"
            f"Target Function: {detection.target_function.name} @ {detection.target_function.addr}\n"
            f"Trace: {detection.traces}\n"
            f"Depth: {detection.depth}\n"
        )
        self.log(log_message, level=self.LEVEL.DETECTION, should_print=True)

        key = (binary_name, detection.target_function.name, detection.source_function.name)
        json_key = "-".join(key)

        # Load the current detection file
        if os.path.exists(self.detections_json_path):
            try:
                with open(self.detections_json_path, "r") as f:
                    detections_data = json.load(f)
            except json.JSONDecodeError:
                detections_data = {"length": 0, "detections": {}}
        else:
            detections_data = {"length": 0, "detections": {}}

        # Update the detection data.
        constraints = constraints = detection.get_constraints()
        if json_key not in detections_data["detections"]:
            detections_data["detections"][json_key] = [constraints]
        else:
            detections_data["detections"][json_key].append(constraints)

        detections_data["length"] = len(detections_data["detections"])


        # Log a minified version of the detection - only the binary, source and checked functions.
        try:
            with open(self.simple_detections_path, "a") as f:
                f.write(json.dumps(json_key) + "\n")
        except IOError as e:
            self.error(f"Failed to write to simple detections log: {e}", should_print=True)

        # Simplify the constraints and update the JSON data
        detection.state.solver.simplify()

        # Log the full detection json back to the file.
        try:
            with open(self.detections_json_path, "w") as f:
                json.dump(detections_data, f, indent=4)
        except IOError as e:
            self.error(f"Failed to write detection logs: {e}", should_print=True)

        
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

