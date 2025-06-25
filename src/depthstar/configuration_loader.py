from json import load
from depthstar.logger import Logger
from depthstar.explosion_detector import ExplosionDetector
from os import path, listdir
import os
import copy
import pkg_resources

DEFAULT_CONFIGURATION_PATH = os.path.join(os.path.expanduser('~'), '.depthstar', 'configurations')
class ConfigurationLoader:
	class __ConfigurationLoader:
		def __init__(self, configuration_directory=DEFAULT_CONFIGURATION_PATH):
			self.projects = []
			self.logger = Logger()
			with open(os.path.join(configuration_directory, "edge_cases.json"), "r") as edge_case_file:
				self.edge_cases = load(edge_case_file)
				self.logger.log(f'Loaded edge case: {self.edge_cases}', self.__class__)

			with open(os.path.join(configuration_directory, "targets.json"), "r") as target_binaries_file:
				# Parse targets.json configuration file
				self.projects = load(target_binaries_file)
				self.parse_target_binaries()
				# self.logger.log(f'Loaded target binaries: {self.projects}', self.__class__)

			with open(os.path.join(configuration_directory, "config.json"), "r") as configuration_file:
				self.configuration = load(configuration_file)
				self.logger.log(f'Loaded configuration: {self.configuration}', self.__class__)

			if not os.path.exists(configuration_directory):
				self.logger.log(f'Configuration directory does not exists: {configuration_directory}')
				return None
			
			# self.logger.log(f'Loaded binaries: {self.projects}', self.__class__)

			# Load aggressiveness settings
			self.base_aggressiveness = self.configuration.get("base_aggressiveness_level_values")
			self.aggressiveness_multiplier = self.configuration.get("aggressiveness_multiplier")

			# Update the explosion detector class accordingly
			ExplosionDetector.BASE_AGGRESSIVENESS = self.base_aggressiveness
			ExplosionDetector.AGGRESSIVENESS_MULTIPLIER = self.aggressiveness_multiplier
			self.logger.debug(f"Loaded aggressiveness multiplier value {self.aggressiveness_multiplier} and base aggressiveness {self.base_aggressiveness} to Explosion Detector")


		def close(self):
			self.edge_case_file.close()

		def parse_target_binaries(self):
			# Parse file names (this is ugly and might want to refactor later)
			for project in self.projects:
				if project['file_name'].split('/')[-1] == '*':
					dir_name = project['file_name'][:-1]
					for file_name in listdir(dir_name):
						project_copy = copy.deepcopy(project)
						project_copy['file_name'] = dir_name + file_name
						self.projects.append(project_copy)
					self.projects.remove(project)

			# Added the edge case target functions to blacklist (no need to begin execution from malloc for example)
			for edge_case in self.edge_cases:
				for function_name in edge_case['function_name']:
					for project in self.projects:
						project['blacklist'].append(function_name)
			
			# Parse things 

		def replace_to_simprocs(self, project):
			for target_function in self.configuration['function_on_arguments']:
				function_to_apply_on_args = self.config['function_on_arguments'][target_function]
				simproc_map = {sp.display_name: sp for sp in project._sim_procedures.values()}
				if function_to_apply_on_args not in simproc_map:
					# This should not happen
					self.logger.log(f'{function_to_apply_on_args} is not found as a simProcedure')
					continue
				function_to_apply_on_args = simproc_map[function_to_apply_on_args]
				self.config['function_on_arguments'][target_function] = function_to_apply_on_args

	instance = None

	@staticmethod
	def get_configuration_loader(configuration_directory):
		if ConfigurationLoader.instance is None:
			ConfigurationLoader.instance = ConfigurationLoader.__ConfigurationLoader(configuration_directory)
		return ConfigurationLoader.instance
