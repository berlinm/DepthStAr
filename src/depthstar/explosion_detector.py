import angr
from threading import Event, Timer
from depthstar.logger import Logger
import signal
from time import sleep

"""
An helper exploration technique to handle explosions
during DSE.
"""


class ExplosionDetector(angr.ExplorationTechnique):
	logger = Logger.get_logger()

	def __init__(self, stashes=('active', 'deferred', 'errored', 'cut'), states_threshold=100, seconds_timeout=10):
		super(ExplosionDetector, self).__init__()
		self._stashes = stashes
		self._threshold = states_threshold
		self._timeout = seconds_timeout
		self.timed_out = Event()
		signal.signal(signal.SIGALRM, self.timeout_callback)
		signal.alarm(self._timeout)

		# For some reason, this is not always working, so temporary patch is:
		Timer(self._timeout + 2, self.verify_timeout)

	def verify_timeout(self):
		if self.timed_out.is_set():
			pass
		signal.signal(signal.SIGALRM, self.timeout_callback)
		signal.alarm(1)

	def timeout_callback(self, signum, frame):
		if self.timed_out.is_set():
			pass
		signal.signal(signal.SIGALRM, self.timeout_callback)
		signal.alarm(1)
		self.logger.log(f'Timeout thrown | frame: {frame}', 'TIMEOUT', should_print=True)
		raise TimeoutError()

	def check_timeout(self, simgr, total):
		if self.timed_out.is_set():
			self.move_all_to_drop(simgr)

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

	def step(self, simgr, stash='active', **kwargs):
		self.logger.log(f'Stepping simulation manger: {simgr}', self.__class__, should_print=True)
		simgr = simgr.step(stash=stash, **kwargs)
		total = self.count_states(simgr)
		self.check_timeout(simgr, total)
		if total >= self._threshold:
			self.logger.log("State explosion detected, over %d states: %s" % (total, str(simgr)), self.__class__)
			self.move_all_to_drop(simgr)
		return simgr
