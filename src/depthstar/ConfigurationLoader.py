from json import load
from src.Logger import Logger
from os import path, listdir
import copy


class ConfigurationLoader:
	class __ConfigurationLoader:
		def __init__(self):
			self.logger = Logger.get_logger()

			self.edge_case_file = open(path.dirname(__file__) + '/../configurations/edge_cases.json', 'r')
			self.target_binaries_file = open(path.dirname(__file__) + '/../configurations/targets.json', 'r')
			self.configuration_file = open(path.dirname(__file__) + '/../configurations/config.json', 'r')

			self.edge_cases = load(self.edge_case_file)
			self.logger.log(f'Loaded edge cases: {self.edge_cases}', self.__class__)

			self.projects = load(self.target_binaries_file)
			self.parse_target_binaries()
			self.logger.log(f'Loaded binaries: {self.projects}', self.__class__)

			self.config = load(self.configuration_file)
			self.logger.log(f'Loaded configurations: {self.projects}', self.__class__)

		def close(self):
			self.edge_case_file.close()

		def parse_target_binaries(self):
			for project in self.projects:
				if project['file_name'].split('/')[-1] == '*':
					dir_name = project['file_name'][:-1]
					for file_name in listdir(dir_name):
						project_copy = copy.deepcopy(project)
						project_copy['file_name'] = dir_name + file_name
						self.projects.append(project_copy)
					self.projects.remove(project)

			for edge_case in self.edge_cases:
				for function_name in edge_case['function_name']:
					for project in self.projects:
						project['blacklist'].append(function_name)

		def replace_to_simprocs(self, project):
			for target_function in self.config['function_on_arguments']:
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
	def get_configuration_loader():
		if ConfigurationLoader.instance is None:
			ConfigurationLoader.instance = ConfigurationLoader.__ConfigurationLoader()
		return ConfigurationLoader.instance
