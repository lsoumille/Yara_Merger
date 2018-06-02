#!/usr/bin/env python
# encoding: utf-8

import os

#Get all folder nanes and remove Android YARA rules
def get_all_yara_folder(folder):
	all_in_dir = os.listdir(folder)
	all_yara_dirs = []
	for dir_file in all_in_dir:
		if not (("." in dir_file) or (dir_file == "Mobile_Malware") or (dir_file == "LICENSE")):
			all_yara_dirs.append(folder + "/" + dir_file)
	return all_yara_dirs


#Get all Yara files
def get_yara_files(folders):
	all_yara_files = []
	for yara_dir in folders:
		all_yara_files_in_dir = os.listdir(yara_dir)
		for yara_file in all_yara_files_in_dir:
			all_yara_files.append(yara_dir + "/" + yara_file)
	return all_yara_files

#Filter Yara files with import math, imphash function and is__osx rule TODO
def remove_incompatible_imports(files):
	yara_files_filtered = []
	for yara_file in files:
		with open(yara_file, 'r') as fd:
			yara_in_file = fd.read()
			if not (("import \"math\"" in yara_in_file) or ("imphash" in yara_in_file)):
				yara_files_filtered.append(yara_file)
	return yara_files_filtered

#Remove private rule is__elf {
def remove_iself_duplicates(files):
	yara_files_filtered = []
	first_elf = True
	to_delete = False
	for yara_file in files:
		with open(yara_file, 'r') as fd:
			yara_in_file = fd.readlines()
			for line in yara_in_file:
				if line.strip() == "private rule is__elf {":
					if first_elf:
						first_elf = False
					else:
						to_delete = True
				if not to_delete:
					yara_files_filtered.append(line)
				if (not first_elf) and line.strip() == "}":
					to_delete = False
	return yara_files_filtered

def main():
	root_yara = "rules_test"
	all_folders = get_all_yara_folder(root_yara)
	all_yara_files = get_yara_files(all_folders)
	all_yara_filered_1 = remove_incompatible_imports(all_yara_files)
	all_yara_filered_2 = remove_iself_duplicates(all_yara_filered_1)
	print(''.join(all_yara_filered_2))

# Main body
if __name__ == '__main__':
	main()