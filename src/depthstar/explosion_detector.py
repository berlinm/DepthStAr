import angr
import threading
from depthstar.logger import Logger
import signal
import time
from enum import Enum
"""
A helper exploration technique to handle explosions
during DSE.
"""

class StepTimeoutException(Exception):
	pass

class ExplosionDetector(angr.ExplorationTechnique):
	logger = Logger()

	def __init__(self, stashes=('active', 'deferred', 'errored', 'cut'), states_threshold=100, seconds_timeout=10):
		super(ExplosionDetector, self).__init__()
		# Input
		self._stashes = stashes	
		self._threshold = states_threshold
		self._timeout = seconds_timeout
		
		# Internal use properties
		self.timed_out = threading.Event()
		self.max_time_limit = time.time() + self._timeout

		# Timer so we know it is time between steps
		timer = threading.Timer(self._timeout + 2, self.set_timeout)
		timer.start()

	def set_timeout(self):
		self.timed_out.set()		


	def move_all_to_drop(self, simgr):
		for stash in self._stashes:
			if hasattr(simgr, stash):
				simgr.move(from_stash=stash, to_stash='_Drop', filter_func=lambda _: True)

	def count_states(self, simgr, only_active=True):
		if only_active:
			return len(getattr(simgr, 'active'))
		total = 0
		for stash in self._stashes:
			if hasattr(simgr, stash):
				total += len(getattr(simgr, stash))
		return total

	def check_timeout(self, simgr, total):
		if self.timed_out.is_set():
			self.move_all_to_drop(simgr)
			return True
		return False

	def step(self, simgr, stash='active', **kwargs):
		result = [None]  # To store the result safely
		exception = [None]  # To store any exception that occurs

		self.logger.debug(message=f'Stepping simulation manger: {simgr}', should_print=True)

		total = self.count_states(simgr)
		if self.check_timeout(simgr, total):
			self.logger.info("Timeout reached, but it was caught between steps, terminating exploration gracefully.")
			raise StepTimeoutException("Exploration exceeded the time limit.")
			return simgr

		if total >= self._threshold:
			self.logger.warning(message="State explosion detected, over %d states: %s" % (total, str(simgr)))
			self.move_all_to_drop(simgr)

		def step_function():
			try:
				result[0] = simgr.step(stash=stash, **kwargs)  # Run the step function
			except Exception as e:
				exception[0] = e  # Store any exception that occurs

		step_thread = threading.Thread(target=step_function)
		step_thread.start()
		
		# Set the time to wait as all the time we have left for this function
		# NOTE: This can theoretically be altered: it is possible to give each step a certain time that is different
		# 		from how much we give the entire function. Currently I don't want to push the threads too much.
		step_thread.join(self.max_time_limit - time.time())

		if step_thread.is_alive():
			# Timeout occurred, but we do NOT forcibly stop the thread
			self.logger.info("Timeout reached, step function is still running in the background.")
			raise StepTimeoutException("Step function exceeded the time limit")
		
		# If an exception was thrown inside the step function, raise it here
		if exception[0]:
			raise exception[0]
		
		return simgr
