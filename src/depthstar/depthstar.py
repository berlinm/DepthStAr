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
from depthstar.constants import *


from enum import Enum
import math

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

	def __init__(self, args):
		configuration_path, out_directory, debug_z3 = args.configuration_path, args.out_directory, args.debug_z3
		# Hidden assumption here that this is the first time the logger is retreived
		self.logger = Logger(out_directory, debug_z3)
		self.cl = ConfigurationLoader.get_configuration_loader(configuration_path)
		self.edge_cases, self.configurations = self.cl.edge_cases, self.cl.configuration

		# Apply configurations
		if 'recursion_limit' in self.configurations:
			value = self.configurations['recursion_limit']
			self.logger.debug(f'Setting recursion limit to {value}')
			sys.setrecursionlimit(value)


		if 'function_on_arguments' in self.configurations:
			self.replacements = self.configurations['function_on_arguments']
			self.logger.debug(f'replacement loaded: {self.replacements}')

	def verify_specific_edge_case(self, project, state, source_function, target_function, vulnerable_value, argument_index):
		"""
		This function is responsible for the verification part upon a BP hits on every call. it must not assume that the function
		is one of an edge case. It is responsible for checking if the function is one, and verifying if it is.

		:param project: DepthstarProject    The object that extends angr's project and holds more depthstar relevant attributes
		:param state: SimState              The current symbolic state which arrived a relevant call instruction
		:param source_function: Function    The function from which the execution began
		:param target_function: Function    The destination function of the call that was made during SE.
		:param vulnerable_value: int       	The vulnerable value we try to detect (e.g. 0)
		:param argument_index: int         	The index (from 0) of the argument we check the value in (e.g. 1)
		:return: bool						Return True if a detection was found
		"""
		argument = project.factory.cc().get_args(state=state, prototype=target_function.prototype)[argument_index]
		if target_function.name in self.replacements:
			self.logger.debug(f'replacing {target_function} with a symbolic function')
			simproc_to_apply = self.replacements[target_function.name]
			simproc_to_apply.execute(state)
			# Extract the result of the simproc
			argument = project.factory.cc().get_return_val(state)
		if state.solver.satisfiable(extra_constraints=[argument == vulnerable_value]):
			self.logger.debug('Found something, simplifying and reporting')
			project.statistics.increment_detections()
			# Report a potential weakness
			state.solver.simplify()
			detection = Detection(project, state, source_function, target_function, argument, funcmap,
								time() - statistics.last_function_start_time, time() - statistics.last_binary_start_time)
			self.logger.log_detection(detection)
			return True
	
		self.logger.info(f'argument {argument_index} cannot be {vulnerable_value}, argument = {argument}')
		return False


	def verify_on_call(self, project, state, source_function, target_function):
		"""
		This function is responsible for the verification part upon a BP hits on every call. it must not assume that the function
		is one of an edge case. It is responsible for checking if the function is one, and verifying if it is.

		:param project: DepthstarProject    The object that extends angr's project and holds more depthstar relevant attributes
		:param state: SimState              The current symbolic state which arrived a relevant call instruction
		:param source_function: Function    The function from which the execution began
		:param target_function: Function    The destination function of the call that was made during SE.
		:return: bool						Return True if a verification was made (i.e. the function that was called is one of an edge case)
		"""
		self.logger.info(f'verifying call to {target_function.name} from {source_function.name}')
		statistics = project.statistics
		statistics.increment_verifications()
		funcmap = project.funcmap
		# The prototype should be there because we executed project.analyses.CompleteCallingConventions
		if not target_function.prototype:
			self.logger.critical(f"The target function of {target_function.name} doesn't have a prototype - will not be able to make any detections")
			return False

		for edge_case in self.edge_cases:
			edge_cases_function_names = edge_case['function_name']
			argument_index = edge_case['argument_index']
			vulnerable_value = edge_case['vulnerable_value']
			for edge_case_function_name in edge_cases_function_names:
				edge_case_function_objects = project.name_funcmap.get(edge_case_function_name, None)
				if not edge_case_function_objects:
					# The edge case wasn't found at all in the project
					continue
				for edge_case_function_object in edge_case_function_objects:
					if target_function.addr != edge_case_function_object.addr:
						# This is not the right function, skip
						continue
					else:
						# The target function matches one of an edge case - verify
						self.verify_specific_edge_case(project, state, source_function, target_function, vulnerable_value, argument_index)
						# Regardless of whether we had a detection, return true for a verification
						return True
		# No verifications were made
		return False


				


		


	
	def handle_function_call(self, project, state, source_function):
		"""
		This function is called automatically by angr with the suitable arguments, every time a bp is hit.
		It is responsible for tracking the functions for dynamic aggressiveness adjustment, and checking whether an AAC is detected.

		:param project: DepthstarProject    The object that extends angr's project and holds more depthstar relevant attributes
		:param state: SimState              The current symbolic state which arrived a relevant call instruction
		:param source_function: Function    The function from which the execution began
		:return: None
		"""
		# Verify input
		function_address = state.addr
		if function_address not in project.kb.functions:
			self.logger.warning(f"Handling function call: call address {function_address} was not found in project's knowledge base as a function.")
			return
		target_function = project.kb.functions.get(function_address, None)
		target_function_name = target_function.name

		# First verify, if function was veirifed (means one of an edge case), return. Else, track.
		did_verifications = self.verify_on_call(project, state, source_function, target_function)
		if did_verifications:
			return
		
		# Target function is not one of an edge case, track it.
		project.track_function_execution(target_function_name)
		return

		# No need to report for edge case functions, they are blacklisted anyway and no reason to ever check them
		

	def place_breakpoint(self, project, state, source_function):
		"""
		Placing a breakpoint for each function that corresponds to the given name target_function_name

		:param project: DepthstarProject    The object that extends angr's project and holds more depthstar relevant attributes
		:param state: SimState             The initial state to place breakpoint on
		:param source_function: Function   The function from which the execution began
		:return: None
		"""
		name_funcmap = project.name_funcmap
		# Adding a breakpoint for each target function
		self.logger.info(f'Setting breakpoints from function {source_function.name}')
		state.inspect.b('call', action=lambda s, _project=project, _source_function=source_function:
			                self.handle_function_call(_project, s, _source_function))


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


	def detect_from_function(self, project, source_function, args):
		"""
		Detects all the loaded edge cases, starting from the given source_function

		:param project: DepthstarProject    The object that extends angr's project and holds more depthstar relevant attributes
		:param source_function: Function     The function from which the execution begins
			:param args:       List[String]      Optional list of arguments passed to the program at execution
		:return: None
		"""

		# initial_state = project.factory.call_state(source_function_address, args=[binary_name] + args)
		initial_state = project.factory.call_state(source_function.addr, *args)
		statistics = project.statistics

		# Get aggressiveness level for function
		aggressiveness_level = project.get_function_aggressiveness(source_function.name)

		self.logger.debug(f"Setting aggressiveness level {aggressiveness_level} for function {source_function.name}")

		# This is a possible optimization, think it is commented out becuase it didn't work in a test but worth looking into it some time
		# if not calls_target_functions(source_function):
		# 	return

		self.place_breakpoint(project, initial_state, source_function)

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


	
	def should_skip(self, project, function_name, main_object_region):
		"""
		Returns whether or not we should skip checking a function (i.e. beginning execution from it)
		:param project: DepthstarProject    The object that extends angr's project and holds more depthstar relevant attributes
		:param function_name: str
		:param main_object_region: Tuple(min_addr: int, max_addr: int)
		:return: enum corresponds to the right action
		"""
		if function_name in project.blacklist:
			self.logger.debug(f'Skipping blacklisted functions: {function_name}', should_print=True)
			return True
		# If one of the functions that correlate to the name given are not in the range we are after, skip
		# NOTE: This is an optimized policy that trades runtime over accuracy
		functions = project.name_funcmap.get(function_name)
		self.logger.debug(f'now checking function {function_name}, (found on addresses {functions}), while main object range is {tuple(hex(address) for address in main_object_region)}')
		if project.is_library_function(function_name):
			self.logger.debug(
				f'Skipping functions from {self.detect_library(project, [function.addr for function in functions])}: {function_name}',
				should_print=True)
			return True

		if self.configurations['default_aggressiveness_level'] == 0 and function_name not in project.function_aggressiveness:
			self.logger.info(f"Default aggressiveness level is 0 and specific function {function_name} was not overridden, skipping")
			return True
		# i.e. Execute!
		return False
		


	def concrete_execute_function(self, project, function_name):
		"""
		Concretely runs a function. used for whitelisted functions to initialize things
		:param project: DepthstarProject    The object that extends angr's project and holds more depthstar relevant attributes
		:param function_name: str           The name of the function to be ran
		:return: None
		"""
		if function_name not in project.name_funcmap:
			self.logger.debug(f'Did not find whitelisted function for concrete execution: {function_name}, skipping', should_print=True)
			return
		function = project.name_funcmap[function_name][0]
		initial_state = project.factory.call_state(function.addr)
		sm = project.factory.simulation_manager(initial_state)
		self.logger.info(f'Runs whitelisted function: {function_name}')
		sm.run()
		self.logger.info(f'Whitelisted function: {function_name} ended', should_print=True)

	def run(self, extra_execution_args=None):
		# Iterate over all the binaries
		if extra_execution_args is None:
			extra_execution_args = []

		for file_map in self.cl.projects:
			binary_name = file_map['file_name']
			project = None
			# Initialize project object
			try:
				# Create angr's project and assign properties from config
				project = DepthStarProject(binary_name=binary_name, 
										   default_aggressiveness_level=self.configurations['default_aggressiveness_level'],
										   function_aggressiveness=file_map.get("aggressiveness", {}),
										   blacklist=file_map.get("blacklist", []),
										   whitelist=file_map.get("whitelist", []),
										   auto_load_libs=False)
				
				self.logger.info(f"Loaded {binary_name} into DepthStarProject")
			
			except Exception as e:
				self.logger.error(f"Failed to load binary {binary_name}: {e}")
				self.logger.debug(f"Stack Trace: {traceback.format_exc()}")
				
				
				continue
			try:
				project.statistics.new_binary()

				self.logger.info(f'Next executing binary: {binary_name}')

				main_object_region = project.regions[MAIN_OBJECT_REGION_INDEX]

				for function_name in project.whitelist:
					self.concrete_execute_function(project, function_name)

				for function_name, functions in tqdm(project.name_funcmap.items()):
					should_skip = self.should_skip(project, function_name, main_object_region)
					if should_skip:
						continue

					for function in functions:
						self.logger.info(f'Next execution function: {function.name}', should_print=True)
						self.detect_from_function(project, function, extra_execution_args)

			except Exception as e:
				self.logger.critical(f'unexpected error {e} while analyzing binary {binary_name}', should_print=True)
				self.logger.debug(f"Stack Trace: {traceback.format_exc()}")
				continue
			finally:
				project.statistics.flush_log(binary_name)
				project.statistics.flush_history_log()



def main():
	parser = argparse.ArgumentParser(description=ASCII_ART_DESCRIPTION)
	# Path arguments
	parser.add_argument("-c", "--configuration_path", type=str, help="Configuration Directory. Should contain 3 files: config.json, targets.json and edge_cases.json", required=True)
	parser.add_argument("-o", "--out_directory", type=str, help="Output Directory. will store all the log and result files in there.", default=os.path.join(os.path.expanduser('~'), '.depthstar', 'output'))
	
	# Heuristic arguments
	parser.add_argument("-d", "--dynamic_agressiveness", action='store_true', help="Allow dynamic aggressiveness adjustment per function. Cost function that determins the aggressiveness can be set with -s/--strategy.")
	parser.add_argument("-s", "--aggressiveness_strategy", type=str, default='LEFM', help="Strategy to determine how we dynamically change aggressiveness level. Has to be used together with -d/--dynamic_agressiveness.")
	
	parser.add_argument("-m", "--allow_configuration_modification", action='store_true', help="")
	
	# Debug Z3
	parser.add_argument("-z", "--debug_z3", action='store_true', help="Use this flag to create another log file that will contain reproducable information about Z3. Mainly should used for debugging purposes if depthstar crashed.")

	
	args = parser.parse_args()
	ds = DepthStar(args)
	ds.run()		
	
