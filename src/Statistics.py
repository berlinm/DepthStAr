from src.Logger import Logger
from time import time
class Statistics:
	"""
	This class is responsible on holding statistics about the execution.
	Example:    Number of total verifications, Number of total detections --- ratio.
	"""
	def __init__(self):
		self.logger = Logger.get_logger()
		self.verifications_count = 0
		self.detections_count = 0
		self.last_function_start_time = 0
		self.last_binary_start_time = 0
		self.detection_times = []
		self.times_history = []

	def increment_detections(self):
		self.detections_count += 1
		self.detection_times.append(time() - self.last_function_start_time)

	def new_binary(self):
		self.last_binary_start_time = time()

	def increment_verifications(self):
		self.verifications_count += 1

	def set_last_function_start(self):
		self.last_function_start_time = time()

	def flush_log(self, headline):
		self.logger.log(headline, 'STATISTICS')
		self.logger.log(f'Verifications count: {self.verifications_count}', 'STATISTICS')
		self.logger.log(f'Detections count: {self.detections_count}', 'STATISTICS')
		self.logger.log(f'Detection Times: {self.detection_times}', 'STATISTICS')
		self.times_history.append(self.detection_times)
		self.detection_times = []

	def flush_history_log(self):
		self.logger.log(f'All Detection Times: {self.times_history}')
