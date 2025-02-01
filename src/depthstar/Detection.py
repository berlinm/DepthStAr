import angr
from depthstar.Logger import Logger


class Detection:
	def __init__(
			self,
			project: angr.Project,
			state: angr.SimState,
			source_function: angr.knowledge_plugins.functions.function,
			target_function: angr.knowledge_plugins.functions.function,
			symbolic_argument,
			funcmap,
			function_time,
			binary_time
	):
		self.traces = []
		self.project = project
		self.state = state
		self.source_function = source_function
		self.target_function = target_function
		self.symbolic_argument = symbolic_argument
		self.logger = Logger.get_logger()
		self.funcmap = funcmap
		self.find_trace_data()
		self.function_time = function_time
		self.binary_time = binary_time

	def describe_address(self, address):
		if address is None:
			return 'No description'
		else:
			try:
				return self.project.loader.describe_addr(self.state.solver.eval(address))
			except:
				return 'No description (2)'

	def find_trace_data(self):
		current_history = self.state.history
		while current_history is not None and len(self.traces) < 4:
			# It is possible to add more information from angr.SimHistory
			current_trace = {
				'jump_source_address': current_history.jump_source if hasattr(current_history, 'jump_source') else None,
				'jump_source_name': self.describe_address(current_history.jump_source if hasattr(current_history, 'jump_source') else None),
				'jump_target_address': current_history.jump_target if hasattr(current_history, 'jump_target') else None,
				'jump_target_name': self.describe_address(current_history.jump_target if hasattr(current_history, 'jump_target') else None),
				'jump_kind': current_history.jumpkind
			}
			self.traces.append(current_trace)
			current_history = current_history.parent
