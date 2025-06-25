import angr
from depthstar.logger import Logger
import pdb
import threading



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
        self.funcmap = funcmap
        self.function_time = function_time
        self.binary_time = binary_time
        self.logger = Logger()

        self.find_trace_data()
        self.constraints = None

        self.logger.debug("Detection object created", should_print=False)


    def get_constraints(self):
        """Returns the constraints of the state, converting them to strings for logging. Assumes self.state is not None."""
        if self.constraints is None:
            self.constraints = [str(c) for c in self.state.solver.constraints]  # Convert constraints to strings for logging
        return self.constraints


    def describe_address(self, address):
        """Returns a human-readable description of an address."""
        # self.logger.debug(f"Describing address {address}", should_print=False)
        if address is None:
            return 'No description'
        try:
            return self.project.loader.describe_addr(self.state.solver.eval(address))
        except (angr.errors.SimValueError, AttributeError):
            return 'No description (2)'

    def find_trace_data(self):
        """Extracts up to 4 trace entries from the state history."""
        count = 0
        current_history = self.state.history.copy()
        self.depth = len(self.state.callstack) - self.project.current_initial_depth

        while current_history is not None:
            # self.logger.debug(f"Finding trace data - count = {count}", should_print=False)
            count += 1
            jump_source = getattr(current_history, 'jump_source', None)
            jump_target = getattr(current_history, 'jump_target', None)
            if not jump_source and not jump_target:
                break  # No useful trace information, exit early
            # self.logger.debug(f"traces before: {len(self.traces)}")
            self.traces.append({
                'jump_source_address': jump_source,
                'jump_source_name': self.describe_address(jump_source),
                'jump_target_address': jump_target,
                'jump_target_name': self.describe_address(jump_target),
                'jump_kind': getattr(current_history, 'jumpkind', None),
            })
            # self.logger.debug(f"traces after: {len(self.traces)}")

            # self.logger.debug(f"{threading.get_native_id()}: Trace entry added: {self.traces[-1]}", should_print=False)
            # pdb.set_trace()
            # self.logger.debug("Accessing current_history.parent")
            current_history = current_history.parent
            # self.logger.debug("Successfully accessed parent")