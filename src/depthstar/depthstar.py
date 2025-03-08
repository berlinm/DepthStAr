import os
import sys
import argparse
from time import time

import angr
from tqdm import tqdm
from depthstar.explosion_detector import ExplosionDetector
from depthstar.logger import Logger
from depthstar.statistics import Statistics
from depthstar.configuration_loader import ConfigurationLoader
from depthstar.detection import Detection

import signal
from enum import Enum
import math

STATES_LIMIT = 100
TIME_LIMIT = 15  # Seconds

STATES_LIMIT_AGGRESSIVE = 10000
TIME_LIMIT_AGGRESSIVE = 600  # Seconds

LIBC_REGION_INDEX = 1
MAIN_OBJECT_REGION_INDEX = 0
CRYPT_REGION_INDEX = 2

ASCII_ART_DESCRIPTION = """
-------------------------------------------------------========================
----------------------------------------------------------=====================
--------------------------------------------------------==-====================
---------------------------------------------------------=====================+
--------------------------------------------------------=====================++
-----------------------+##+--------+#%@%#*=-------#%%#=---==================+++
----------------------=%--%----=%@%=--*===%@@+---+@--**=--=================++++
-----------------------=*+--=##+-----=*===+++*%%+-=#%*==----===============++++
-----------------------:--=%+----=%%%%%@@%%*++++#@+--------================++++
-------------------+@=---#*----+%*..:---:.-#@%+++*%@=--=+=++==============+++++
------------------------=*---+%+.+%##%%@@@#=.+@*+++%%-----*#==============+++++
---------------+@+++=-::**--=%-.##...%%@@@@@%.+@+++%@%%%%%%+==============+++++
------------=#-=++++++++##--+#.*@=-=#%%@@@@@@+-%%++%%#*******+++=========++++++
----------=%######%%%%%#%#==#+.@@%%%%%@@@@@@@%:%@+*%@%%%%%#====+%@+======++++++
-----------------=======*#==##.#@@@@@@@@@@@@@*-%%**%%+=+++++++==========+++++++
-------------=%%==++++++##==+%=:#@@@@@@@@@@@*:+@***%%*++++=============++++++++
----------------------==##===*@#.+@@@@@@@@%-:%@##**%@%%#####@@+======++++++++++
-------------------#+---=%%+=++%@+-:=*#*-:-*#-#@%#%@*======+%%*=====+++++++++++
----------------------+*--#@%*+++*%@%%%%%@%%@#-%#@%+==============+++++++++++++
=--------------=%-++-=*=%-*#+%@#++****%*****%@%+==#@+============++++++++++++++
===--=-=--------+#*=------#+=#%*@@%#*#%**#%@%%@@#+++%%*========++++++++++++++**
===========---------------#-=%#=@+@@@@@@@@*%=+%+@@#**#@@*======+++++++++++++***
=================---------#-=%#=%=@=#%@*+@=#==%=%*%@%#%@*+===++++++++++++++****
====================-----+%-=%*=%=@=#%%+=%=%#=#=@===#%#***++++++++++++++++*****
======================---==-=%+=%=@+#%%==@=%*+#=@======+++++++++++++++++*******
==========================--+@%=%=@+*%%+=@-#=+#=@+======+++++++++++++++********
===========================-===+%=@+*@@#=@-#+##=@=======+++++++++++++*******##*
===============================+#*@=====+%+%*===@+===+++++++++++++++********##*
===============================+%%@==##+==@%@===+==+++++++++++++++********#####"""

class ACTION_ON_FUNCTION(Enum):
		SKIP = 0
		EXECUTE = 1
		AGGRESSIVE_EXECUTE = 2

class DepthStar:

	def __init__(self, configuration_path, out_directory):
		self.logger = Logger(out_directory)
		self.logger.info(f'Starting analysis with configurations:' + '\n' +
		           f'states limit: {STATES_LIMIT} time limit: {TIME_LIMIT}' + '\n' +
		           f'aggressive state limit: {STATES_LIMIT_AGGRESSIVE} aggressive time limit: {TIME_LIMIT_AGGRESSIVE}')
		self.cl = ConfigurationLoader.get_configuration_loader(configuration_path)
		self.edge_cases, self.projects, self.configurations = self.cl.edge_cases, [file_map['file_name'] for file_map in self.cl.projects], self.cl.configuration
		self.all_statistics = {binary_name: Statistics() for binary_name in self.projects}
		# Apply configurations
		if 'recursion_limit' in self.configurations:
			value = self.configurations['recursion_limit']
			self.logger.debug(f'Setting recursion limit to {value}')
			sys.setrecursionlimit(value)

		# Initializing the binaries, the whitelists and blacklists

		# Doing this in the loop to catch exceptions
		project_map = {}
		for name in self.projects:
			try:
				project_map[name] = angr.Project(name, auto_load_libs=False)
			except:
				pass
		self.projects = project_map
		# projects = {name: angr.Project(name) for name in projects}
		self.blacklists = {file_map['file_name']: file_map['blacklist'] for file_map in self.cl.projects}
		self.whitelists = {file_map['file_name']: file_map['whitelist'] for file_map in self.cl.projects}
		self.require_aggressive = {file_map['file_name']: file_map['aggressive'] for file_map in self.cl.projects}

		# Identifying regions for libc, main executable, and cryptographic libraries
		self.regions = {name: self.create_regions(project) for name, project in self.projects.items()}

		# ---- Takes ~2 min. for each executable that is loaded ----
		# Initializing the control flow graph, and the functions names

		cfgs = {name: self.cfg_from_project(project) for name, project in self.projects.items()}
		# idfers = {name: project.analyses.Identifier(cfg=cfgs[name]) for name, project in self.projects.items()}

		# Building a convenient function maps by name and by address
		self.funcmaps = {name: self.get_funcmap(project) for name, project in self.projects.items()}
		self.name_funcmaps = {name: self.get_name_funcmap(self.funcmaps[name]) for name in self.projects.keys()}

		if 'function_on_arguments' in self.configurations:
			self.replacements = self.configurations['function_on_arguments']
			self.logger.debug(f'replacement loaded: {self.replacements}')

	


	def cfg_from_project(self, project):
		self.logger.debug(f"now loading {project}", should_print=True)
		return project.analyses.CFGFast(force_complete_scan=False, data_references=False,
		                                resolve_indirect_jumps=True, show_progressbar=True,
		                                heuristic_plt_resolving=True, indirect_jump_target_limit=1000000)


	def get_funcmap(self, project):
		funcmap = {address: function_object for address, function_object in project.kb.functions.items()}
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


	def create_crypt_region(self, project):
		"""
		Identifies and returns the regions in file that corresponds to a cryptographic library
		:param project: Project                                The project object
		:return: region: Tuple[min_addr: int, max_addr: int]
		"""
		crypt_binary = [obj for obj in project.loader.all_elf_objects if 'crypt' in obj.binary_basename.lower()]
		crypt_binary = crypt_binary[0] if crypt_binary else None
		if crypt_binary is None:
			return None
		self.logger.debug(f'Crypto binary region detected: {crypt_binary}')
		return (
			crypt_binary.min_addr, crypt_binary.max_addr
		)


	def create_regions(self, project):
		"""
		Identifies and returns a list with 2 regions in the file that corresponds to:
		1. The main object library, containing all the user defined functions and data
		2. The standard libc library
		:param project: Project                                The project object
		:return: regions: List[Tuple(min_addr: int, max_addr: int)]
		"""
		current_file_binary = project.loader.all_objects[0]
		libc_binary = [obj for obj in project.loader.all_elf_objects if 'libc-' in obj.binary_basename]
		if libc_binary:
			libc_binary = libc_binary[0]
			libc_regions = (libc_binary.min_addr, libc_binary.max_addr)
		else:
			libc_regions = None
		regions = [region for region in [
			(current_file_binary.min_addr, current_file_binary.max_addr),
			libc_regions,
			self.create_crypt_region(project)
		] if region]
		self.logger.info(f'current binary: {current_file_binary}\nlibc binary: {libc_binary if libc_binary else "Not Found"}', "GETTING REGIONS")
		return regions


	


	def verify_on_call(self, binary_name, state, source_function, target_function, vulnerable_value=0, argument_index=0):
		"""
		This function is called automatically by angr with the suitable arguments, every time a bp is hit.

		:param binary_name: str             The name of the project that represents the target binary.
		:param state: SimState              The current symbolic state which arrived a relevant call instruction
		:param source_function: Function    The function from which the execution began
		:param target_function: Function    The targeted function (e.g. realloc : Function)
		:param vulnerable_value: int        The vulnerable value we try to detect (e.g. 0)
		:param argument_index: int          The index (from 0) of the argument we check the value in (e.g. 1)
		:return: None
		"""
		self.logger.info(f'verifying call to {target_function.name} from {source_function.name}', 'VERIFICATION')
		statistics = self.all_statistics[binary_name]
		statistics.increment_verifications()
		project = self.projects[binary_name]
		funcmap = self.funcmaps[binary_name]
		argument = project.factory.cc().arg(state, argument_index)
		if target_function.name in self.replacements:
			self.logger.debug(f'replacing {target_function} with a symbolic function')
			simproc_to_apply = self.replacements[target_function.name]
			simproc_to_apply.execute(state)
			# Extract the result of the simproc
			argument = project.factory.cc().get_return_val(state)
		if state.solver.satisfiable(extra_constraints=[argument == vulnerable_value]):
			self.logger.detection('Found something, simplifying and reporting')
			statistics.increment_detections()
			# Report a potential weakness
			state.solver.simplify()
			detection = Detection(project, state, source_function, target_function, argument, funcmap,
			                      time() - statistics.last_function_start_time, time() - statistics.last_binary_start_time)
			self.logger.log_detection(detection)
			return

		self.logger.info(f'argument cannot be {vulnerable_value}, argument = {argument}')


	def place_breakpoint(self, binary_name, state, target_function_name, source_function, argument_index, vulnerable_value):
		"""
		Placing a breakpoint for each function that corresponds to the given name target_function_name

		:param binary_name: str            The targeted binary name
		:param state: SimState             The initial state to place breakpoint on
		:param target_function_name: str   The targeted function name (e.g. realloc : str)
		:param source_function: Function   The function from which the execution began
		:param vulnerable_value: int       The vulnerable value we try to detect (e.g. 0)
		:param argument_index: int         The index (from 0) of the argument we check the value in (e.g. 1)
		:return: None
		"""
		name_funcmap = self.name_funcmaps[binary_name]
		if target_function_name not in name_funcmap:
			return False
		target_functions = name_funcmap[target_function_name]

		# Adding a breakpoint for each target function
		for target_function in target_functions:
			self.logger.info(f'Setting breakpoint from {source_function.name} to {target_function.name}')
			state.inspect.b('call', function_address=target_function.addr,
			                action=lambda s, _binary_name=binary_name, _source_function=source_function,
			                              _target_function=target_function,
			                              _argument_index=argument_index,
			                              _vulnerable_value=vulnerable_value:
			                self.verify_on_call(_binary_name, s, _source_function, _target_function,
			                               vulnerable_value=_vulnerable_value, argument_index=_argument_index))


	def calls_target_functions(self, source_function):
		"""
		Returns true if one of the targeted functions is called from the source function
		:param source_function:
		:return:
		"""
		functions_called = [f.name for f in source_function.functions_called()]
		for edge_case in self.edge_cases:
			for target_function in edge_case['function_name']:
				if target_function in functions_called:
					self.logger.info(f'{target_function} detected in {source_function.name}', 'OPTIMIZATION')
					return True
		self.logger.debug(f'No target function calls detected from {source_function.name}. Skipping!')
		return False


	def detect_from_function(self, binary_name, source_function, aggressive, args):
		"""
		Detects all the loaded edge cases, starting from the given source_function

		:param binary_name: str              The targeted binary name
		:param source_function: Function     The function from which the execution begins
		:param aggressive: Boolean           Whether we should dedicate extra resources (space and time) to
											 execute this function (e.g. for main function in an executable)
		:param args:       List[String]      Optional list of arguments passed to the program at execution
		:return: None
		"""

		project = self.projects[binary_name]
		source_function_address = source_function.addr
		# initial_state = project.factory.call_state(source_function_address, args=[binary_name] + args)
		initial_state = project.factory.call_state(source_function_address, *args)
		statistics = self.all_statistics[binary_name]
		#
		# if not calls_target_functions(source_function):
		# 	return
		for edge_case in self.edge_cases:
			target_function_names = edge_case['function_name']
			argument_index = edge_case['argument_index']
			vulnerable_value = edge_case['vulnerable_value']

			for target_function_name in target_function_names:
				self.place_breakpoint(binary_name, initial_state, target_function_name, source_function, argument_index,
				                 vulnerable_value)

		# Creating simulation manager with the initialized state
		sm = project.factory.simulation_manager(initial_state)

		# Limiting state and time of the analysis
		if not aggressive:
			ed = ExplosionDetector(states_threshold=STATES_LIMIT, seconds_timeout=TIME_LIMIT)
		else:
			ed = ExplosionDetector(states_threshold=STATES_LIMIT_AGGRESSIVE, seconds_timeout=TIME_LIMIT_AGGRESSIVE)

		sm.use_technique(ed)
		statistics.set_last_function_start()

		try:
			# Start exploring
			sm.explore()
		except TimeoutError:
			# clean up force stopped simgr
			ed.timed_out.set()
			total = ed.count_states(sm)
			self.logger.warning(f'Timeout caught | {total} states: {str(sm)}')
			statistics.detection_times.append(math.inf)
			ed.check_timeout(sm, total)
		except Exception as e:
			self.logger.critical(f'unexpected error {e} while analyzing source function {source_function.name}',
			           should_print=True)
		finally:
			# cancel the alarm if timeout was not reached
			signal.alarm(0)


	# def get_regions(self, binary_name, regions_to_get):
	# 	"""
	# 	Extracts the wanted regions given a binary name
	# 	:param binary_name: str                     The name of the binary
	# 	:param regions_to_get: List[index: int]     A list of indices to get the regions of
	# 	:return:
	# 	"""
	# 	current_binary_regions = self.regions[binary_name]
	# 	regions_to_return = []
	# 	for index in regions_to_get:
	# 		regions_to_return.append(current_binary_regions[index])
	# 	return regions_to_return


	def detect_library(self, project, addresses):
		"""
		Find and return the object in which the address given resides
		:param project: angr.Project
		:param addresses: List[address: int]
		:return: Object: List[str]
		"""
		all_objects = project.loader.all_objects
		found_objects = set()
		for address in addresses:
			# Starting from 1 because we want to skip the main object
			for current_object in all_objects[1:]:
				current_range = (current_object.min_addr, current_object.max_addr)
				if address in range(*current_range):
					found_objects.add(current_object.binary_basename)
					break
		return found_objects if found_objects else "<library not found>"


	def find_action_for_functions(self, binary_name, function_name, main_object_region):
		"""
		Finds the right action for functions (skip, check, or aggressive check)
		:param binary_name: str
		:param function_name: str
		:param main_object_region: Tuple(min_addr: int, max_addr: int)
		:return: enum corresponds to the right action
		"""
		# There are several functions that correlate to a certain name
		functions = []
		functions = self.name_funcmaps[binary_name][function_name]

		if function_name in self.require_aggressive[binary_name]:
			return ACTION_ON_FUNCTION.AGGRESSIVE_EXECUTE
		if function_name in self.blacklists[binary_name]:
			self.logger.debug(f'Skipping blacklisted functions: {function_name}', should_print=True)
			return ACTION_ON_FUNCTION.SKIP

		# If one of the functions that correlate to the name given are not in the range we are after, skip
		# NOTE: This is an optimized policy that trades runtime over accuracy
		self.logger.debug(f'now checking function {function_name}, (found on addresses {functions}), while main object range is {tuple(hex(address) for address in main_object_region)}')
		if any(
				[(function.addr not in range(*main_object_region))
				 for function in functions]
		):
			self.logger.debug(
				f'Skipping functions from {self.detect_library(self.projects[binary_name], [function.addr for function in functions])}: {function_name}',
				should_print=True)
			return ACTION_ON_FUNCTION.SKIP
		return ACTION_ON_FUNCTION.EXECUTE


	def concrete_execute_function(self, binary_name, function_name):
		"""
		Concretely runs a function. used for whitelisted functions to initialize things
		:param binary_name: str             The name of the binary
		:param function_name: str           The name of the function to be ran
		:return: None
		"""
		if function_name not in self.name_funcmaps[binary_name]:
			self.logger.debug(f'Did not find whitelisted function for concrete execution: {function_name}, skipping', should_print=True)
			return
		function = self.name_funcmaps[binary_name][function_name][0]
		project = self.projects[binary_name]
		initial_state = project.factory.call_state(function.addr)
		sm = project.factory.simulation_manager(initial_state)
		self.logger.info(f'Runs whitelisted function: {function_name}')
		sm.run()
		self.logger.info(f'Whitelisted function: {function_name} ended', should_print=True)

	def run(self, extra_execution_args=None):
		# Iterate over all the binaries
		if extra_execution_args is None:
			extra_execution_args = []
		for binary_name, project in self.projects.items():
			self.all_statistics[binary_name].new_binary()

			self.logger.info(f'Next executing binary: {binary_name}')

			main_object_region = self.regions[binary_name][MAIN_OBJECT_REGION_INDEX]

			for function_name in self.whitelists[binary_name]:
				self.concrete_execute_function(binary_name, function_name)

			for function_name, functions in tqdm(self.name_funcmaps[binary_name].items()):
				desirable_action = self.find_action_for_functions(binary_name, function_name, main_object_region)
				if desirable_action == ACTION_ON_FUNCTION.SKIP:
					continue
				aggressive = desirable_action == ACTION_ON_FUNCTION.AGGRESSIVE_EXECUTE

				for function in functions:
					self.logger.info(f'Next execution function: {function.name}', should_print=True)
					self.detect_from_function(binary_name, function, aggressive, extra_execution_args)
			self.all_statistics[binary_name].flush_log(binary_name)


def main():
	parser = argparse.ArgumentParser(description=ASCII_ART_DESCRIPTION)
	parser.add_argument("-c", "--configuration_path", type=str, help="Configuration Directory. Should contain 3 files: config.json, targets.json and edge_cases.json", required=True)
	parser.add_argument("-o", "--out_directory", type=str, help="Output Directory. will store all the log and result files in there.", default=os.path.join(os.path.expanduser('~'), '.depthstar', 'output'))
	args = parser.parse_args()
	ds = DepthStar(args.configuration_path, args.out_directory)
	ds.run()
	for stat in self.all_statistics.values():
		stat.flush_history_log()
	
