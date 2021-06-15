from datetime import datetime
from json import dumps
from os import path, mkdir, listdir
import csv


class Logger:
	def __init__(self):
		pass

	class __Logger:
		def __init__(self):
			out_path = path.dirname(__file__) + '/../out/'
			previous_logs = listdir(out_path)
			previous_logs = [log for log in previous_logs if log.isnumeric()]
			log_index = max([int(d) for d in previous_logs]) + 1
			self.current_out_path = out_path + str(log_index)
			mkdir(self.current_out_path)
			self.log_file = open(self.current_out_path + '/log.txt', 'w+')
			open(self.current_out_path + '/report.csv', 'w+').close()
			self.log_file.write("\n\nNEW RUN\n-------------------------------------------------------------\n")
			self.log_file.close()
			self.current_logger = -1
			self.detections = {}
			self.report_id = 0
			open(self.current_out_path + '/simple_detections.txt', 'w+').close()
			open(self.current_out_path + '/detections.json', 'w+').close()

		def log_detection(self, detection, lightweight=True):
			self.report(detection)
			binary_name = detection.project.filename
			self.log(
				f'project: {binary_name} | '
				f'state: {detection.state}'
				+ '\n' +
				f'source function: {detection.source_function.name} | At address: {detection.source_function.addr}'
				+ '\n' +
				f'target function: {detection.target_function.name} | At address: {detection.target_function.addr}'
				+ '\n' +
				# f'ARGUMENT (SYMBOLIC): {detection.symbolic_argument}'
				# + '\n' +
				f'trace data: {detection.traces}'
				+ '\n' +
				f'Examples: Not supported yet',
				'DETECTION', should_print=True)
			path_constraints = detection.state.solver.constraints
			detections_file = open(self.current_out_path + '/detections.json', 'w+')
			simple_detections_file = open(self.current_out_path + '/simple_detections.txt', 'a+')
			constraints = "" # f'{str(path_constraints)} -------  SYMBOLIC ARGUMENT  ---------0 {detection.symbolic_argument}'
			key = (binary_name, detection.target_function.name, detection.source_function.name)
			if key not in self.detections:
				self.detections[key] = [constraints]
				simple_detections_file.write(dumps(list(key)))
			else:
				self.detections[key].append(constraints)
			detections_file.write(
				dumps([f'length = {len(self.detections)}', {
					' | '.join(key): value for key, value in self.detections.items()
				}]))
			simple_detections_file.close()
			detections_file.close()

		def highlight(self):
			self.log_file.write('\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n')

		def log(self, log_text, logger="", should_print=False):
			self.log_file = open(self.current_out_path + '/log.txt', 'a')
			if self.current_logger != logger:
				if logger == 'DETECTION':
					self.highlight()
				self.log_file.write(f'{logger}:\n')
				self.current_logger = logger
			logging_message = f'\n[{datetime.now()}]\t' + log_text + '\n'

			self.log_file.write(logging_message)
			self.log_file.close()
			#
			# if should_print:
			# 	print(logging_message)

		def report(self, detection):
			report_line = [str(x) for x in
			               [self.report_id,
			                detection.project.filename,
			                hex(detection.state.addr),
			                detection.function_time,
			                detection.binary_time,
			                detection.source_function.name,
			                detection.target_function.name
			                ]]
			new = True
			with open(self.current_out_path + '/report.csv', 'a+') as report_file:
				reader = csv.reader(report_file)
				for row in reader:
					if row[2] == hex(detection.state.addr) and row[5] == detection.source_function.name and row[6] == detection.target_function.name:
						new = False
						break
				if new:
					writer = csv.writer(report_file)
					writer.writerow(report_line)
					self.report_id += 1

		def close(self):
			self.log_file.close()

	instance = None

	@staticmethod
	def get_logger():
		if Logger.instance is None:
			Logger.instance = Logger.__Logger()
		return Logger.instance
