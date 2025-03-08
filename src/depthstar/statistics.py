from depthstar.logger import Logger
from time import time

class Statistics:
    """
    This class holds execution statistics, such as:
    - Total verifications and detections
    - Detection times
    - Execution history
    """

    def __init__(self):
        self.logger = Logger()
        self.verifications_count = 0
        self.detections_count = 0
        self.last_function_start_time = None
        self.last_binary_start_time = None
        self.detection_times = []
        self.times_history = []

    def increment_detections(self):
        """Increase the detection count and log the function execution time."""
        if self.last_function_start_time is not None:
            elapsed_time = time() - self.last_function_start_time
            self.detection_times.append(elapsed_time)
        self.detections_count += 1

    def new_binary(self):
        """Start tracking a new binary execution."""
        self.last_binary_start_time = time()

    def increment_verifications(self):
        """Increase the verification count."""
        self.verifications_count += 1

    def set_last_function_start(self):
        """Mark the start time of the current function execution."""
        self.last_function_start_time = time()

    def flush_log(self, headline):
        """Flush the current statistics to the logger and reset detection times."""
        self.logger.info(message=headline)
        self.logger.info(f'Verifications count: {self.verifications_count}')
        self.logger.info(f'Detections count: {self.detections_count}')
        self.logger.info(f'Detection Times: {self.detection_times}')

        # Save history before resetting
        self.times_history.append(self.detection_times[:])  
        self.detection_times.clear()  

    def flush_history_log(self):
        """Log the complete history of detection times."""
        self.logger.info(f'All Detection Times: {self.times_history}')
