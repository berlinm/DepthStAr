import os
import sys
import argparse
import threading
import traceback
from time import time

import angr
from tqdm import tqdm
from depthstar.explosion_detector import ExplosionDetector, StepTimeoutException
from depthstar.logger import Logger
from depthstar.statistics import Statistics
from depthstar.configuration_loader import ConfigurationLoader
from depthstar.detection import Detection
from depthstar.depthstar_project import DepthStarProject


from enum import Enum
import math

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


class DepthStar:

	def __init__(self, configuration_path, out_directory):
		self.logger = Logger(out_directory)
		self.cl = ConfigurationLoader.get_configuration_loader(configuration_path)
		self.edge_cases, self.configurations = self.cl.edge_cases, self.cl.configuration


		self.projects = {}
		for file_map in self.cl.projects:
			binary_name = file_map['file_name']
			try:
				# Create angr's project
				project = DepthStarProject(binary_name, auto_load_libs=False)
				
				# Assign properties from config
				project.function_aggressiveness = file_map.get("aggressiveness", {})
				project.blacklist = file_map.get("blacklist", [])
				project.whitelist = file_map.get("whitelist", [])
				project.statistics = Statistics()

				# Identifying regions for libc, main executable, and cryptographic libraries
				project.regions = self.create_regions(project)
				
				# ---- Takes some time for each executable that is loaded ----
				# Initializing the control flow graph, and the functions names
				project.cfg = self.cfg_from_project(project)

				# Building a convenient function maps by name and by address
				project.funcmap = self.get_funcmap(project)
				project.name_funcmap = self.get_name_funcmap(project.funcmap)
				
				self.projects[binary_name] = project
				
				
				self.logger.info(f"Loaded {binary_name} into DepthStarProject")
			
			except Exception as e:
				self.logger.warning(f"Failed to load binary {binary_name}: {e}")


		# Apply configurations
		if 'recursion_limit' in self.configurations:
			value = self.configurations['recursion_limit']
			self.logger.debug(f'Setting recursion limit to {value}')
			sys.setrecursionlimit(value)


		if 'function_on_arguments' in self.configurations:
			self.replacements = self.configurations['function_on_arguments']
			self.logger.debug(f'replacement loaded: {self.replacements}')

	


	def cfg_from_project(self, project):
		self.logger.debug(f"now loading {project}", should_print=True)

		project_cfg = project.analyses.CFGFast(force_complete_scan=False, data_references=False,
		                                resolve_indirect_jumps=True, show_progressbar=True,
		                                heuristic_plt_resolving=True, indirect_jump_target_limit=1000000)
		project.analyses.CompleteCallingConventions(recover_variables=True)
		return project_cfg


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
		self.logger.info(f'verifying call to {target_function.name} from {source_function.name}')
		statistics = self.projects[binary_name].statistics
		statistics.increment_verifications()
		project = self.projects[binary_name]
		funcmap = project.funcmap
		# The prototype should be there because we executed project.analyses.CompleteCallingConventions
		if not target_function.prototype:
			self.logger.critical(f"The target function of {target_function.name} doesn't have a prototype - will not be able to make any detections")
			return
		argument = project.factory.cc().get_args(state=state, prototype=target_function.prototype)[argument_index]
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

		self.logger.info(f'argument {argument_index} cannot be {vulnerable_value}, argument = {argument}')


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
		name_funcmap = self.projects[binary_name].name_funcmap
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


	def detect_from_function(self, binary_name, source_function, args):
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
		statistics = self.projects[binary_name].statistics

		# Get aggressiveness level for function
		aggressiveness_level = self.configurations['default_aggressiveness_level']
		if source_function.name in self.projects[binary_name].function_aggressiveness:
			aggressiveness_level = self.projects[binary_name].function_aggressiveness[source_function.name]

		self.logger.debug(f"Setting aggressiveness level {aggressiveness_level} for function {source_function.name}")

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
		ed = ExplosionDetector(aggressiveness_level=aggressiveness_level)

		sm.use_technique(ed)
		statistics.set_last_function_start()

		try:
			# Start exploring
			sm.explore()
		except StepTimeoutException:
			# Clean up force stopped simgr
			ed.set_timeout()
			total = ed.count_states(sm)
			self.logger.warning(f'Timeout caught | {total} states: {str(sm)}')
			statistics.detection_times.append(math.inf)
			active_threads = threading.enumerate()
			self.logger.info(f"FYI: There are currently {len(active_threads)} active (stuck) threads")
		except Exception as e:
			self.logger.critical(f'unexpected error {e} while analyzing source function {source_function.name}',
			           should_print=True)
			self.logger.debug(f"Stack Trace: {traceback.format_exc()}")


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


	
	def should_skip(self, binary_name, function_name, main_object_region):
		"""
		Returns whether or not we should skip checking a function (i.e. beginning execution from it)
		:param binary_name: str
		:param function_name: str
		:param main_object_region: Tuple(min_addr: int, max_addr: int)
		:return: enum corresponds to the right action
		"""
		if function_name in self.projects[binary_name].blacklist:
			self.logger.debug(f'Skipping blacklisted functions: {function_name}', should_print=True)
			return True
		# If one of the functions that correlate to the name given are not in the range we are after, skip
		# NOTE: This is an optimized policy that trades runtime over accuracy
		functions = self.projects[binary_name].name_funcmap.get(function_name)
		self.logger.debug(f'now checking function {function_name}, (found on addresses {functions}), while main object range is {tuple(hex(address) for address in main_object_region)}')
		if any(
				[(function.addr not in range(*main_object_region))
				 for function in functions]
		):
			self.logger.debug(
				f'Skipping functions from {self.detect_library(self.projects[binary_name], [function.addr for function in functions])}: {function_name}',
				should_print=True)
			return True

		if self.configurations['default_aggressiveness_level'] == 0 and function_name not in self.projects[binary_name].function_aggressiveness:
			self.logger.info(f"Default aggressiveness level is 0 and specific function {function_name} was not overridden, skipping")
			return True
		# i.e. Execute!
		return False
		


	def concrete_execute_function(self, binary_name, function_name):
		"""
		Concretely runs a function. used for whitelisted functions to initialize things
		:param binary_name: str             The name of the binary
		:param function_name: str           The name of the function to be ran
		:return: None
		"""
		if function_name not in self.projects[binary_name].name_funcmap:
			self.logger.debug(f'Did not find whitelisted function for concrete execution: {function_name}, skipping', should_print=True)
			return
		function = self.projects[binary_name].name_funcmap[function_name][0]
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
			self.projects[binary_name].statistics.new_binary()

			self.logger.info(f'Next executing binary: {binary_name}')

			main_object_region = self.projects[binary_name].regions[MAIN_OBJECT_REGION_INDEX]

			for function_name in self.projects[binary_name].whitelist:
				self.concrete_execute_function(binary_name, function_name)

			for function_name, functions in tqdm(self.projects[binary_name].name_funcmap.items()):
				should_skip = self.should_skip(binary_name, function_name, main_object_region)
				if should_skip:
					continue

				for function in functions:
					self.logger.info(f'Next execution function: {function.name}', should_print=True)
					self.detect_from_function(binary_name, function, extra_execution_args)
			self.projects[binary_name].statistics.flush_log(binary_name)


def main():
	parser = argparse.ArgumentParser(description=ASCII_ART_DESCRIPTION)
	parser.add_argument("-c", "--configuration_path", type=str, help="Configuration Directory. Should contain 3 files: config.json, targets.json and edge_cases.json", required=True)
	parser.add_argument("-o", "--out_directory", type=str, help="Output Directory. will store all the log and result files in there.", default=os.path.join(os.path.expanduser('~'), '.depthstar', 'output'))
	args = parser.parse_args()
	ds = DepthStar(args.configuration_path, args.out_directory)
	ds.run()
	for project in ds.projects.values():
		project.statistics.flush_history_log()
	
