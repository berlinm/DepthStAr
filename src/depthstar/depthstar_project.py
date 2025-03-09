import angr

class DepthStarProject(angr.Project):
    def __init__(self, binary_path, *args, **kwargs):
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

    def is_function_blacklisted(self, function_name):
        """Check if a function is in the blacklist."""
        return function_name in self.blacklist

    def is_function_whitelisted(self, function_name):
        """Check if a function is in the whitelist."""
        return function_name in self.whitelist

    def get_function_aggressiveness(self, function_name, default=3):
        """Return aggressiveness level for a function, defaulting to 3 if not set."""
        return self.function_aggressiveness.get(function_name, default)
