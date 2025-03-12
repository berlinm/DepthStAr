import angr
from depthstar.constants import *
from depthstar.logger import *

class DepthStarProject(angr.Project):

    AGGRESSIVENESS_STEP_INTERVAL = 10  # Increase aggressiveness every X calls

    def __init__(self, binary_name, default_aggressiveness_level, function_aggressiveness, blacklist, whitelist, *args, **kwargs):
        # Initialize angr's project
        super().__init__(binary_name, *args, **kwargs)
        self.initialize_angr_project()

        self.logger = Logger()

        self.binary_name=binary_name

        # Function-specific settings
        self.function_aggressiveness = function_aggressiveness  # {"function_name": aggressiveness_level}
        self.blacklist = blacklist  # List of functions to skip
        self.whitelist = whitelist  # List of functions to execute concretely
        
        # Control Flow Graph & Function Mapping
        self.cfg = None  # CFG object
        self.funcmap = {}  # Maps function addresses to function objects
        self.name_funcmap = {}  # Maps function names to addresses

        # Execution tracking
        self.execution_count = {}  # Tracks how often functions are executed
        self.detection_results = []  # Stores detection reports

        self.default_aggressiveness_level = default_aggressiveness_level


        self.binary_name = binary_name
        self.args = args  # Store extra positional args
        self.kwargs = kwargs  # Store extra keyword args

    def initialize_angr_project(self):
        # Identifying regions for libc, main executable, and cryptographic libraries
        self.regions = self.create_regions()
        
        # ---- Takes some time for each executable that is loaded ----
        # Initializing the control flow graph, and the functions names
        self.cfg = self.create_cfg()

        # Building a convenient function maps by name and by address
        self.funcmap = self.get_funcmap()
        self.name_funcmap = self.get_name_funcmap(self.funcmap)

    
    
    def get_funcmap(self):
        funcmap = {address: function_object for address, function_object in self.kb.functions.items()}
        return funcmap
    
    
    def get_name_funcmap(self, funcmap):
        """
        Creates and returns a map from name to a list of functions, corresponding to that name
        :param funcmap: Dict[name: str, function_list: List[function: Function]]
        :return:
        """
        name_funcmap = {}
        for addr, func in funcmap.items():
            if func.name in name_funcmap:
                name_funcmap[func.name].append(func)
            else:
                name_funcmap[func.name] = [func]
        return name_funcmap

    def create_crypt_region(self):
        """
        Identifies and returns the regions in file that corresponds to a cryptographic library
        :return: region: Tuple[min_addr: int, max_addr: int]
        """
        crypt_binary = [obj for obj in self.loader.all_elf_objects if 'crypt' in obj.binary_basename.lower()]
        crypt_binary = crypt_binary[0] if crypt_binary else None
        if crypt_binary is None:
            return None
        self.logger.debug(f'Crypto binary region detected: {crypt_binary}')
        return (crypt_binary.min_addr, crypt_binary.max_addr)


    def create_cfg(self):
        self.logger.debug(f"now loading {self.binary_name}", should_print=True)

        project_cfg = self.analyses.CFGFast(force_complete_scan=False, data_references=False,
                                        resolve_indirect_jumps=True, show_progressbar=True,
                                        heuristic_plt_resolving=True, indirect_jump_target_limit=1000000)
        self.analyses.CompleteCallingConventions(recover_variables=True)
        return project_cfg


    def create_regions(self):
        """
        Identifies and returns a list with 2 regions in the file that corresponds to:
        1. The main object library, containing all the user defined functions and data
        2. The standard libc library
        :param project: Project                                The project object
        :return: regions: List[Tuple(min_addr: int, max_addr: int)]
        """
        current_file_binary = self.loader.all_objects[0]
        libc_binary = [obj for obj in self.loader.all_elf_objects if 'libc-' in obj.binary_basename]
        if libc_binary:
            libc_binary = libc_binary[0]
            libc_regions = (libc_binary.min_addr, libc_binary.max_addr)
        else:
            libc_regions = None
        regions = [region for region in [
            (current_file_binary.min_addr, current_file_binary.max_addr),
            libc_regions,
            self.create_crypt_region()
        ] if region]
        self.logger.info(f'current binary: {current_file_binary}\nlibc binary: {libc_binary if libc_binary else "Not Found"}', "GETTING REGIONS")
        return regions




    def is_function_blacklisted(self, function_name):
        """Check if a function is in the blacklist."""
        return function_name in self.blacklist

    def is_function_whitelisted(self, function_name):
        """Check if a function is in the whitelist."""
        return function_name in self.whitelist

    def track_function_execution(self, function_name):
        """Tracks function execution dynamically and adjusts aggressiveness."""
        self.logger.debug(f"Tracking an execution of {function_name}. Total executions: {self.function_execution_count[function_name]}")
        if function_name not in self.function_execution_count:
            self.function_execution_count[function_name] = 0
        
        if function_name not in self.function_aggressiveness:
            self.function_aggressiveness[function_name] = self.default_aggressiveness_level

        self.function_execution_count[function_name] += 1

        # Increase aggressiveness every 10 calls, up to level MAX_AGGRESSIVENESS_LEVEL
        if self.function_execution_count[function_name] % AGGRESSIVENESS_STEP_INTERVAL == 0:
            self.function_aggressiveness[function_name] = min(MAX_AGGRESSIVENESS_LEVEL, self.function_aggressiveness[function_name] + 1)
            self.logger.info(f"Updated aggressiveness level for {function_name}: {self.function_aggressiveness[function_name]}")

    def get_function_aggressiveness(self, function_name):
        """Returns the dynamically adjusted aggressiveness level for a function."""
        # If function does not exist, create with default value
        if function_name not in self.function_aggressiveness:
            self.function_aggressiveness[function_name] = self.default_aggressiveness_level
        
        return self.function_aggressiveness.get(function_name)
