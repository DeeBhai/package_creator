#!/usr/bin/env python3
import logging
from logging.handlers import RotatingFileHandler
import os
import datetime
import json
import argparse
import sys
import shutil
import hashlib
import tarfile
import glob
import re
import traceback
import errno
from hashlib import md5
import base64
from collections import defaultdict
from operator import xor

details_str = 'details'
artefacts_str = 'artifacts'

python_run_abspath = os.path.abspath(__file__)

class key_strings():
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name_key = "name"
        self.version_key = "version"
        self.commitid_key = "commit_id"
        self.checksum_key = "checksum"

        self.system_date_key = "system_date"
        self.details_checksum_key = "checksum"
        self.details_version = "version"
class configs:
    output_json_name = "artifacts_info.json"
    artefact_dir_name = "artifacts"

class Logger:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            self.logger = logging.getLogger()
            self.logger.setLevel(logging.DEBUG)

            fh = RotatingFileHandler('packager.log', maxBytes=20000, backupCount=1)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            fh.setFormatter(formatter)

            console_op = logging.StreamHandler(stream=sys.stdout)
            console_op.setLevel(logging.INFO)

            self.logger.addHandler(fh)
            self.logger.addHandler(console_op)
        except:
            raise Exception("Unable to create Log File, check File Permissions")
        
class FileHandler:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filepath = os.path.abspath(__file__)

    def get_pkg_basename(self, abs_filepath) -> str:
        name = os.path.basename(abs_filepath)
        regex_pattern1 = r"(\w+?)_([vV]?)(\d+).?"
        regex_pattern2 = r"(\w+)([vV]?).*"
        if re.search(regex_pattern1, name):
            try:
                name_list = re.match(regex_pattern1, name)
                name = name_list.groups()[0]
            except:
                if name_list:
                    print(name_list.groups())
                name = name.split('.')[0]

        elif re.search(regex_pattern2, name):
            print('#')
            try:
                name_list = re.match(regex_pattern2, name)
                name = name_list.groups()[0]
            except:
                if name_list:
                    print(name_list.groups())
                name = name.split('.')[0]
        return name

    def generate_md5(self, fname, chunk_size=4096)->str:
        """
        Function which takes a file name and returns md5 checksum of the file
        """
        try:
            hash = hashlib.md5()
            with open(fname, "rb") as f:
                # Read the 1st block of the file
                chunk = f.read(chunk_size)
                # Keep reading the file until the end and update hash
                while chunk:
                    hash.update(chunk)
                    chunk = f.read(chunk_size)
        except IOError as err:
            raise

        return hash.hexdigest()

    def read_input_json(self, filepath=python_run_abspath):
        json_load = {}
        try:
            if (os.path.isfile(filepath)):
                with open(filepath, 'r') as ip_json:
                    json_load = json.load(ip_json)
                return json_load
            else:
                raise Exception("Provided Path is Not a Valid FilePath")
        except ValueError:
            self.logger.info("Incorrect JSON value or syntax")
        except:
            raise
    
    def write_output_json(self, op_json_data={}, path=os.getcwd()):
        try:
            json_path = os.path.join(path, configs.output_json_name)
            with open(json_path, 'w') as op_json:
                json.dump(op_json_data, op_json, indent=1)
        except:
            raise Exception("Unable to write json to the path")

    def copy_artefact(self, target_path=None, src_filepath=None):
        """
        All Files will be copied to the data folder
        """
        self.logger.debug("Copying: {} to {}".format(src_filepath, target_path))
        try:
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            shutil.copy(src_filepath, target_path)
        except:
            raise

    def delete_existing(self, path=None):
        try:
            if path is not None:
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    pass
        except:
            raise
    
    def perform_housekeeping(self, pkgname):
        """ 
        Deletes all files and folders having above pkgname as regex
        """
        try:
            pkg_basename = self.get_pkg_basename(pkgname)
            # Get all folders starting with above basename and delete them
            files_list = glob.glob(pkg_basename+"*")
            for file in files_list:
                self.logger.debug("PKG File/Folder: {} going to be deleted".format(file))
                self.delete_existing(os.path.join(os.getcwd(), file))
        except:
            self.logger.warn("Unable to perform housekeeping properly")

    def create_zip(self, archive_path, name, file_list=[]):
        if(os.path.exists(name)):
            self.delete_existing(name)

        tf = None
        try:
            tf = tarfile.open(os.path.join(archive_path, str(name)), mode="w:gz")
            for iter in file_list:
                if os.path.isfile(iter):
                    tf.add(iter)
                else:
                    tf.add(iter, recursive=True)
                self.delete_existing(iter)
        except:
            raise Exception("Unable to create Archive")
        finally:
            if tf:
                tf.close()

class callbacks(key_strings):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.name = None
        self.commit_id = None
        self.version = None
        self.checksum = None

        # Variables to fill in Details Section
        self.global_checksum = None
        self.global_version = None

    def get_release_date(self) -> str:
        date_obj = datetime.date.today()
        date = date_obj.strftime("%d-%b-%Y")
        return str(date)
    
    def get_details_info(self, dict={}):
        dict[self.system_date_key] = self.get_release_date()
        dict[self.details_checksum_key] = self.get_global_checksum()
        dict[self.details_version] = self.get_global_version()

    def get_artefact_details(self, dict={}):
        dict[self.name_key] = self.get_name()
        dict[self.version_key] = self.get_version()
        dict[self.commitid_key] = self.get_commit_id()
        dict[self.checksum_key] = self.get_checksum()

    def get_name(self) -> str:
        return self.name

    def get_version(self) -> str:
        return self.version

    def get_commit_id(self) -> str:
        return self.commit_id

    def get_checksum(self) -> str:
        return self.checksum
    
    def get_global_checksum(self) -> str:
        return self.global_checksum

    def get_global_version(self) -> str:
        return self.global_version


class jsonMapper(Logger, FileHandler, callbacks, key_strings):
    def __init__(self, input_json_path=python_run_abspath, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.input_json = {}
        self.ip_json_abspath = os.path.abspath(input_json_path)
        self.ip_json_dir = os.path.dirname(os.path.abspath(input_json_path))

        # String key to parse input config
        self.output_name_str = "output_name"
        self.filepath_str = "filepath"
        self.keymap_str = "keymap"
        self.add_info_str = "add_info"
        self.version_str = "version"
        self.commit_id_str = "commit_id"
        self.package_name_key = "package_name"

        # output json skeleton
        self.output_json = {details_str:{}, artefacts_str:{}}

        # Variables used
        self.package_name = "default_pkg.tar.gz"
        self.package_extension = None
        self.package_path = None

    def process_json_input(self):
        try:
            self.input_json = self.read_input_json(self.ip_json_abspath)

            if not self.input_json:
                self.logger.info("JSON provided can't be decoded")
                sys.exit(0)

            # Extract Details and Artifacts
            for key, value in self.input_json.items():
                if(key in details_str):
                    self.process_details_dict(key, value)
                    self.perform_housekeeping(self.package_name)
                    self.package_path = os.path.join(os.getcwd(), self.package_name)
                elif self.package_path is None:
                    self.logger.error("Key Details should be processed first")
                    sys.exit(0)
                elif(key in artefacts_str):
                    self.process_artefacts_dict(key, value)
                else:
                    self.logger.error("Unknown Key found in JSON: {}".format(key))
                    raise Exception("Unknown Key to parse in INPUT JSON")
        except:
            self.logger.info(traceback.format_exc())
            self.logger.error("PACKAGING FAILED...")
        else:
            self.update_end_info()
            self.logger.debug(json.dumps(self.output_json, indent=2))
            self.write_output_json(self.output_json, path=self.package_path)
            
            # Make sure to use folder hierarchy which you want in the archive
            # However, dont provide absolute paths here as archive will inherit that folder hierarchy
            file_list = [
                os.path.join(os.path.basename(self.package_path)), 
                ]

            pkg_name = self.package_name
            if self.package_extension is not None:
                pkg_name = pkg_name + self.package_extension
            else:
                pkg_name = pkg_name + '.tar.gz'

            self.create_zip(os.getcwd(), pkg_name, file_list)
            self.delete_existing(self.package_path)
            if self.package_extension is not None:
                os.rename(pkg_name, self.package_name + self.package_extension)
            else:
                os.rename(pkg_name, self.package_name)
            self.logger.info("PACKAGING SUCCESS.")
        finally:
            pass
    
    def update_end_info(self):
        """
        Update the details which needs to be processed at end,
        just before package creation
        """
        try:
            self.output_json[details_str][self.details_checksum_key] = self.global_checksum
        except:
            self.logger.warn("Unable to get write Package Checksum")

    def process_details_dict(self, key_str, data):
        try:
            package_name_info = []
            if self.package_name_key in data.keys():
                package_name_info = list(data[self.package_name_key])
                del(data[self.package_name_key])
            else:
                self.logger.warn("Key: \{{}\} not Found, Using PkgName {}".format(self.package_name_key, self.package_name))

            if self.global_version != "None":
                if(len(package_name_info) == 2):
                    self.package_name = package_name_info[0] + "_" + self.global_version
                    self.package_extension = package_name_info[1]
                elif(len(package_name_info) == 1):
                    self.package_name = package_name_info[0] + "_" + self.global_version
                else:
                    pass
            else:
                if(len(package_name_info) == 2):
                    self.package_name = package_name_info[0]
                    self.package_extension = package_name_info[1]
                elif(len(package_name_info) == 1):
                    self.package_name = package_name_info[0]
                else:
                    pass
        except:
            # Nothing to do since as Pkg name is not mandatory for packaging
            pass

        try:
            for key, value in data.items():
                self.output_json[details_str][key] = value
            
            # now add fixed keys to it
            local_dict = {}
            self.get_details_info(local_dict)

            for key, value in local_dict.items():
                self.output_json[details_str][key] = value
        except:
            raise

    def process_artefacts_dict(self, key_str, data):
        md5sum_list = []
        if isinstance(data, list):
            for item in data:
                # Local Variables used
                gen_checksum = None
                version = None
                commitid = None

                info_stat = self.validate_artefact_data(item)
                if info_stat:
                    dest_path = os.path.join(self.package_path, configs.artefact_dir_name, item[self.output_name_str])
                    self.copy_artefact(dest_path, os.path.join(self.ip_json_dir, item[self.filepath_str]))

                    """ Here, filepath of source file is taken so that 
                    any error during copy can be caught during extraction and verification
                    """
                    gen_checksum = self.generate_md5(os.path.join(self.ip_json_dir, item[self.filepath_str]))
                    
                    if(item[self.add_info_str]):
                        for key,value in item[self.add_info_str].items():
                            if(key in self.version_str):
                                version = value
                            elif(key in self.commit_id_str):
                                commitid = value
                            else:
                                self.logger.debug("Key: {} mapping not added".format(key))

                    self.name = item[self.output_name_str]                          # Generated Name
                    self.version = version                                          # Generated Version
                    self.commit_id = commitid                                       # Generated CommitID
                    self.checksum = gen_checksum                                    # Generated Checksum

                    self.add_to_dict(item[self.keymap_str])
                    md5sum_list.append((self.checksum))
                else:
                    self.logger.debug("Skipped O/P Name: {}".format(item[self.output_name_str]))

            self.global_checksum = self.gen_combined_checksum(md5sum_list)

    def gen_combined_checksum(self, md5sum_list=[]) -> str:
        final_hash = int(md5sum_list[0], 16)
        for each in md5sum_list[1:]:
            final_hash = xor(final_hash, int(each, 16))
        return(str(final_hash)[:32])

    def add_to_dict(self, keymap=[]):        
        local_dict = {}
        local_dict_val = {}
        self.get_artefact_details(local_dict_val)

        final_key = keymap[-1]
        keymap = keymap[:-1]

        temp_dict = self.output_json[artefacts_str]
        
        for iter in keymap:
            if iter not in temp_dict:
                temp_dict[iter] = {}
            temp_dict = temp_dict[iter]
        temp_dict[final_key] = local_dict_val

    def validate_artefact_data(self, data) -> bool:
        status = True
        try:
            if(data[self.output_name_str] is None) or (data[self.filepath_str] is None):
                self.logger.warn("Check the artefact data: \n{}".format(data))
                status = False
        except:
            self.logger.warn("Exception while Parsing: \n{}".format(data))
            status = False

        return status

    def log_print(self, msg=""):
        self.logger.debug("{}".format(msg))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir', dest = "INPUT_JSON", default = os.getcwd(), type = str, help = 'Specify the PATH to Input JSON')
    parser.add_argument('-v', '--version', dest = "VERSION_STR", default = None, type = str, help = 'Specify the Package Version')
    args = vars(parser.parse_args())

    ip_json_path = str(args["INPUT_JSON"])
    package_version = str(args["VERSION_STR"])

    try:
        if not ip_json_path:
            print("Provide DIR path as argument")
            sys.exit(0)

        jm = jsonMapper(input_json_path=ip_json_path)
        
        if package_version is None:
            jm.log_print("WARN: Package Version is None")
        else:
            jm.global_version = package_version
        
        jm.process_json_input()
    except:
        traceback.print_exc()