import angr
from depthstar.constants import *

class DepthStarProject(angr.Project):

    AGGRESSIVENESS_STEP_INTERVAL = 10  # Increase aggressiveness every X calls

    def __init__(self, binary_path, default_aggressiveness_level, *args, **kwargs):
        super().__init__(binary_path, *args, **kwargs)

        # Function-specific settings
        self.function_aggressiveness = {}  # {"function_name": aggressiveness_level}
        self.blacklist = []  # List of functions to skip
        self.whitelist = []  # List of functions to execute concretely
        
        # Control Flow Graph & Function Mapping
        self.cfg = None  # CFG object
        self.funcmap = {}  # Maps function addresses to function objects
        self.name_funcmap = {}  # Maps function names to addresses

        # Execution tracking
        self.execution_count = {}  # Tracks how often functions are executed
        self.detection_results = []  # Stores detection reports

        self.default_aggressiveness_level = default_aggressiveness_level

    def is_function_blacklisted(self, function_name):
        """Check if a function is in the blacklist."""
        return function_name in self.blacklist

    def is_function_whitelisted(self, function_name):
        """Check if a function is in the whitelist."""
        return function_name in self.whitelist

    def track_function_execution(self, function_name):
        """Tracks function execution dynamically and adjusts aggressiveness."""
        if function_name not in self.function_execution_count:
            self.function_execution_count[function_name] = 0
        
        if function_name not in self.function_aggressiveness:
            self.function_aggressiveness[function_name] = self.default_aggressiveness_level

        self.function_execution_count[function_name] += 1

        # Increase aggressiveness every 10 calls, up to level MAX_AGGRESSIVENESS_LEVEL
        if self.function_execution_count[function_name] % AGGRESSIVENESS_STEP_INTERVAL == 0:
            self.function_aggressiveness[function_name] = min(MAX_AGGRESSIVENESS_LEVEL, self.function_aggressiveness[function_name] + 1)

    def get_function_aggressiveness(self, function_name):
        """Returns the dynamically adjusted aggressiveness level for a function."""
        # If function does not exist, create with default value
        if function_name not in self.function_aggressiveness:
            self.function_aggressiveness[function_name] = self.default_aggressiveness_level
        
        return self.function_aggressiveness.get(function_name, self.config_loader.get_base_aggressiveness())
