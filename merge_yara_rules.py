#!/usr/bin/env python
# encoding: utf-8

import os

#Get all folder nanes and remove Android YARA rules
def get_all_yara_folder(folder):
	all_in_dir = os.listdir(folder)
	all_yara_dirs = []
	for dir_file in all_in_dir:
		if not (("." in dir_file) or (dir_file == "Mobile_Malware") or (dir_file == "LICENSE")):
			all_yara_dirs.append(root_yara + "/" + dir_file)
	return all_yara_dirs


#Get all Yara files
def get_yara_files(folder)
	all_yara_files = []
	for yara_dir in folder:
		all_yara_files_in_dir = os.listdir(yara_dir)
		for yara_file in all_yara_files_in_dir:
			all_yara_files.append(yara_dir + "/" + yara_file)
	return all_yara_files

#Filter Yara files with import math and imphash function
def remove_incompatible_imports(files)
	yara_files_filtered = []
	for yara_file in all_yara_files:
		with open(yara_file, 'r') as fd:
			yara_in_file = fd.read()
			if not (("import \"math\"" in yara_in_file) or ("imphash" in yara_in_file)):
				yara_files_filtered.append(yara_file)
	return yara_files_filtered

def main():
	root_yara = "rules"
	args = sys.argv[1:]
	if not args:
		print('usage: [--flags options] [inputs] ')

	sys.exit(1)

# Main body
if __name__ == '__main__':
	main()