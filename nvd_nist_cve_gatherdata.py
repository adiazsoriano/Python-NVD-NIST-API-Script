"""
nvd_nist_cve_gatherdata.py

It is a CLI based script that takes in command-line arguments.
The purpose of the script is to interact with the National 
Vulnerability Database's (NVD) Common Vulnerabilities and 
Exposures (CVE) RESTful API provided by the National Institute 
of Standards and Technology (NIST). Using the given schema of 
the data, it pulls from this API using Python to then format 
the data into a CSV format as raw data. 

More information here: https://nvd.nist.gov/developers/vulnerabilities


Author: Angel Diaz-Soriano
Date Created: 8/29/2023
"""
import os
import sys
import requests
import time
import json
import re
import argparse
import progressbar
import datetime
import data_mapping
from calendar import monthrange
from dotenv import load_dotenv
from io import TextIOWrapper

# loads variables from the .env file
load_dotenv()

# constants
PADDING_WIDTH = 30
CURRENT_YEAR = datetime.date.today().year

# class definitions
class CliArgValidation:
    """ This class hosts the various validation functions used for argparse.
    """

    @staticmethod
    def validate_year(value) -> int:
        """Validates the year given a string value. This is used  in conjuction
        with argparse's :meth:`add_argument` function as "type."

        Args:
            value (any): Value passed in for validation.

        Raises:
            argparse.ArgumentTypeError: Raised if the year is not within the 1988 - (current year) range.
                                        Raised if there is a ValueError as a result of non-numeric
                                        input.

        Returns:
            int: A valid "year" value.
        """
        try:
            year = int(value)

            if year < 1988 or year > CURRENT_YEAR:
                raise argparse.ArgumentTypeError(f'Please keep this within range of 1988 - {CURRENT_YEAR} (inclusive).')

            return year
        except ValueError:
            raise argparse.ArgumentTypeError("Please enter a proper non-negative real number.")
    
    @staticmethod
    def validate_data_map(value) -> str:
        """ The general validation function which decides whether to parse 
            using json or other txt files.

        Args:
            value (any): The value inputted, assumed to be a filename.

        Raises:
            argparse.ArgumentTypeError: Raised if the given value isn't a filename with a clear file extension.
                                        Raised if the given value causes errors with types.
                                        Raised if the given value leads to an non-existent file.

        Returns:
            str: A valid filename with valid contents.
        """
        try:
            split_value = str(value).split(".")
            
            if len(split_value) != 2:
                raise argparse.ArgumentTypeError("Please enter a filename with a file extension. Try either \"example.txt\" or \"example.json\"")
            
            if split_value[1] == "json":
                return CliArgValidation.validate_data_map_json(value)
            else:
                return CliArgValidation.validate_data_map_txt(value)

        except (ValueError, AttributeError):
            raise argparse.ArgumentTypeError("This is not a valid format for files.")
        except FileNotFoundError:
            raise argparse.ArgumentTypeError("This file does not exist, please enter a file that exists.")
        
    @staticmethod
    def validate_data_map_json(value) -> str:
        """ Validates the given value (which is a filename) to see whether the
            contents are within the format of:
                {
                    [CSV_HEADER] : LIST(),
                    [CSV_HEADER] : LIST(),
                    ...
                }

                This follows a loose definition of the given format, and does not
                include the content, merely the format. There may be cases where
                specific formats can cause an issue.

        Args:
            value (any): The value inputted, assumed to be a filename.

        Raises:
            argparse.ArgumentTypeError: Raised if the value leads to content that isn't in a valid JSON format.
                                        Raised if the file content does not contain a \"dict\" as the primary
                                        structure
                                        Raised if the key value pairs do not contain lists as the values.
                                        Raised if the content of each list of the value is neither str nor int.


        Returns:
            str: A valid filename with valid contents.
        """
        format_error_msg = "Make sure that the structure is as follows: \n" \
                            "{\n" \
                            "\t\"csvHeader\":[a list with a combination of strings and ints],\n" \
                            "\t\"example\":[\"item\",0,...,\"item\"],\n" \
                            "\t...\n" \
                            "}\n"
        

        with open(str(value), "r") as data_map_file:
            try:
                first_char = data_map_file.read(1)
                data_map_file.seek(0)
                if first_char != "{":
                    raise argparse.ArgumentTypeError(f'Please ensure that \"{value}\" is in a valid json object format.')

                raw_json = data_map_file.read()
                json_data = json.loads(raw_json)

                if not isinstance(json_data,dict):
                    raise argparse.ArgumentTypeError(format_error_msg)
                
                for items in json_data.values():
                    if not isinstance(items,list):
                        raise argparse.ArgumentTypeError(format_error_msg)
                    
                    for item in items:
                        if not isinstance(item,(str,int)):
                            raise argparse.ArgumentTypeError(format_error_msg)
                        
            except json.JSONDecodeError:
                raise argparse.ArgumentTypeError(f'Please ensure that \"{value}\" is in the proper JSON format.')
    
        return str(value)
    
    @staticmethod
    def validate_data_map_txt(value) -> str:
        """ Validates the given value (which is a filename) to see whether the
            contents are within the format of:
                [CSV_HEADER]:[DATA],[DATA],...,[DATA]

                This follows a loose definition of the given format, and does not
                include the content, merely the format. There may be cases where
                specific formats can cause an issue.

        Args:
            value (any): The value inputted, assumed to be a filename.

        Raises:
            argparse.ArgumentTypeError: Raised if the file is empty.
                                        Raised if the specific format is not followed.

        Returns:
            str: A valid filename with valid contents.
        """
        with open(str(value), "r") as data_map_file:

            #checking for potential file empty
            if not data_map_file.read().strip():
                raise argparse.ArgumentTypeError("Please make sure the file has content.")
            data_map_file.seek(0)
            
            #loosely checking for content format
            for line in data_map_file:
                if not re.match(r'^[A-Za-z0-9#_]+:[A-Za-z0-9]+(?:,[A-Za-z0-9]+)*$',line):
                    raise argparse.ArgumentTypeError(f'Please configure \"{value}\" in ' \
                                                    'the following format per line: [CSV_HEADER]:[DATA],[DATA],...,[DATA]')
                
        return str(value)

    @staticmethod
    def validate_create_mapping(value) -> str:
        """ Validates given the value (which is the output mode) to make sure
            it fits within "txt" or "json"

        Args:
            value (any): Value passed in for validation.

        Raises:
            argparse.ArgumentTypeError: Raised if "txt" or "json" are not present in the given value
                                        Raised if not a valid type or value.

        Returns:
            str: A valid output mode in str form.
        """
        try:
            value = str(value).strip().lower()

            args_to_check = ("json","txt")
            if value not in args_to_check:
                raise argparse.ArgumentTypeError(f'{value} is invalid. Please enter either \"json\" or \"txt\" as an argument.')
            
            return value

        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError("Make sure that the value is a valid.")
    
    @staticmethod
    def validate_limit_mapping(value) -> int:
        """ Valides given the value (assumed to be a number) to make sure it is
            a valid number between 1 - 100,000.

            It is good to note that when this function isn't utilized, the default
            value is 0. Which is valid for the program, but the user can't input
            this value since it isn't necessary.

        Args:
            value (any): Value passed in for validation.

        Raises:
            argparse.ArgumentTypeError: Raised if the value isn't a valid number.
                                        Raised if the value isn't within 1 - 100,000.

        Returns:
            int: _description_
        """
        try:
            value = int(value)

            if value < 1 or value > 100_000:
                raise argparse.ArgumentTypeError("Make sure that the value is between 1 and 100,000.")

            return value
        except ValueError:
            raise argparse.ArgumentTypeError("Make sure that this is a valid positive number.")
    
    @staticmethod
    def validate_extra_args(value) -> str:
        """Validates the extra args to make sure that they include only the characters
        specified in the URL arguments.

        Args:
            value (any): A value to be validated.

        Raises:
            argparse.ArgumentTypeError: Raised if there are any extra characters not specified.
                                        Raised if the an element of the list "args_to_check" appear in value

        Returns:
            str: A valid string, not based on content but characters.
        """
        args_to_check = ("pubStartDate", "pubEndDate", "resultsPerPage", "startIndex")
        value = str(value).strip()
        
        if not re.match(r'^[\w*.:/=-]+$',value):
            raise argparse.ArgumentTypeError("Please make sure to enter a proper argument for the API URL. ")
        
        for arg in args_to_check:
            if value.find(arg) != -1:
                raise argparse.ArgumentTypeError(f'\"{arg}\" exists within the internal API call, please omit this argument.')
        
        return value
    

class FileLineInfo:
    """ This class keeps track of the number of lines during operation.

        Attributes:
            count (int): The line counter of a file.
    """
    def __init__(self):
        """ Constructor for FileLineInfo, instantiates attributes.
        """
        self.count = 0
    
    def increm_count(self) -> None:
        """Increments count by 1.
        """
        self.count += 1
    
    def get_count(self) -> int:
        """Returns count.

        Returns:
            int: Returns the current count of the instance.
        """
        return self.count
    

class ProgramStatus:
    """ This class manages the status of the program through a progress bar.

        Attributes:
            pb (progressbar.Progressbar|None): Serves as the main progress bar.
            max_val (int): Indicates the total increments of the progress.
            widgets (list|None): The progress bar's styling.
            counter (int): The current iteration of the progress.
            status (str): Displays the current status of the program.
            progress (str): Displays the overall progress in readible form.
    """

    def __init__(self, max_val: int):
        """ Constructor for ProgramStatus, instantiates attributes.

        Args:
            max_val (int): Required for the total increments of the progress bar.
        """
        self.pb = None
        self.max_val = max_val
        self.widgets = None
        self.counter = 0
        self.status = "..."
        self.progress = "..."

    
    def create_progress_bar(self) -> None:
        """ Creates the progress bar with custom widgets
        """
        self.widgets = [
            self.status,
            progressbar.Percentage(),
            " (", self.progress ,") ",
            progressbar.Bar(), " ",
            progressbar.Timer(), " | " , progressbar.AdaptiveETA()
        ]

        self.pb = progressbar.ProgressBar(max_value=self.max_val, widgets=self.widgets)
    
    def update_progress_bar(self, status: str = None, progress: str = None, increment_total = False) -> None:
        """ Updates the progress bar given status, progress, or total increments.

        Args:
            status (str, optional): Presents the current status. Defaults to None.
            progress (str, optional): Presents the current progress. Defaults to None.
            increment_total (bool, optional): Indicates where to increment the total progress or not. Defaults to False.

        Raises:
            AttributeError: Raised if the update function is invoked before invoking :meth:`create_progress_bar`
        """
        if self.pb:
            if status:
                self.status = status
            if progress:
                self.progress = progress

            #self.widgets[0] correlates to status
            #self.widgets[3] correlates to progress
            self.widgets[0] = self.status
            if self.counter != self.max_val:
                self.widgets[3] = self.progress
            
            if increment_total:
                self.counter += 1

            self.pb.update(self.counter)
        else:
            raise AttributeError("Please make sure to invoke example_obj.create_progress_bar() before updating.")


    def _close_progress_bar(self) -> None:
        """ Finishes the progress bar, should not be invoked outside of class.
        """
        if self.pb:
            self.pb.finish()
    
    def __del__(self):
        """ Destructor which closes the progress bar once the object is out of scope.
        """
        if not self.pb._finished:
            self._close_progress_bar()

# function definitions
def conduct_gather(output_filename: str = "output.csv", 
                     start_year: int = 1988, 
                     end_year: int = CURRENT_YEAR,
                     headers_filename: str = "csvHeaders.txt",
                     extra_args: str = ""
                   ) -> None:
    """Conducts the main 'gather' operation that writes API response info to the output file

    Args:
        output_filename (str, optional): The file name of the output file. Defaults to "output.csv".
        start_year (int, optional): Starting published year to gather data (inclusive). Defaults to 1988.
        end_year (int, optional): Ending published year to gather data (inclusive). Defaults to CURRENT_YEAR.
        headers_filename (str, optional): The infomation needed to parse through JSON tree-structure. Defaults to "csvHeaders.txt".
        extra_args (str, optional): Extra arguments that be given to the API. Defaults to "".
    """
    try:
        total_iter = ((end_year - start_year + 1) * 12)

        rowcount = FileLineInfo()

        prog_status = ProgramStatus(total_iter)
        prog_status.create_progress_bar()

        api_key_exists = False
        if os.environ.get("api_key"):
            api_key_exists = True

        json_tree_info = retrieve_json_info(headers_filename)

        with open(output_filename, "w", encoding="utf-8") as output_f:
            write_csv_headers_tofile(output_f, json_tree_info)
            rowcount.increm_count()

            for month, year in iterate_month_year(start_year,end_year,throttle=3):
                prog_status.update_progress_bar(f'{"Retrieving data...":{PADDING_WIDTH}}',f'mo {month}, yr {year}',True)

                api_results = nvd_api_gather(year,month,extra_args,api_key_exists,prog_status)

                for result in api_results:
                    write_json_data_tofile(output_f, result["vulnerabilities"],json_tree_info,rowcount,prog_status)
        
        prog_status.update_progress_bar(f'{"Written to file. ":{PADDING_WIDTH}}')
    except IOError:
        graceful_exit(1,prog_status)
    except Exception as e:
        graceful_exit(prog_status=prog_status)

def retrieve_json_info(headers_filename:str):
    json_tree_info = None
    with open(headers_filename, "r") as input_headers_f:
        # with the validation from before, the assumption here is that
        # both files are formatted correctly.
        if headers_filename.split(".")[1] == "json":
            json_tree_info = json.loads(input_headers_f.read())
        else:
            json_tree_info = read_json_tree_info(input_headers_f)

    return json_tree_info
            

def read_json_tree_info(file: TextIOWrapper) -> dict:
    """Reads the information from a file that contains the assumed format of:
        [CSV_HEADER]:[DATA],[DATA],...,[DATA]
        
        Where CSV_HEADER is the header written at the top of a CSV formatted file.
        DATA contains any data that enables the program to traverse the JSON schema
        provided by the API. Since the JSON response is typically a big tree-like strucutre,
        this information is formatted in such a way to enable this traversal. It enables
        the user to custom pick data for output.

        This runs into the issue of requiring the user to understand the API response's 
        tree structure, rather than automating the process (this will be a work in-progress).

    Args:
        file (TextIOWrapper): The file object that will be read from.

    Returns:
        dict: It will return a dictionary of the CSV header information provided by the file.
    """
    json_tree_info = dict()

    for line in file:
        line = line.strip()
        current_header = line.split(":")[0]
        current_tree_info = line.split(":")[1].split(",")

        json_tree_info[current_header] = current_tree_info

    return json_tree_info

def write_csv_headers_tofile(file: TextIOWrapper, headers: dict) -> None:
    """Solely writes the given csv headers to an output file.

        Requires that the headers dictionary to contain the structure of:
            {
                [CSV_HEADER] : LIST(),
                [CSV_HEADER] : LIST(),
                ...
            }
        :func:`read_json_tree_info` creates a dictionary with this format.

    Args:
        file (TextIOWrapper): The file to be written to.
        headers (dict): The dict that contains the headers.
    """
    output_header = ",".join(headers.keys())
    
    file.write(output_header + "\n")


def write_json_data_tofile(file: TextIOWrapper, data: list, headers: dict, rowcount: FileLineInfo = None, prog_status: ProgramStatus = None) -> None:
    """Writes the json data provided by the :func:`call_nvd_api` function and 
       formated by :meth:`json.loads` function. The function is intended to
       work with the "vulnerabilities" list of the json response of the 
       NVD NIST CVE API. 

    Args:
        file (TextIOWrapper): The file to be written to.
        data (list): The list of data that contains objects.
        headers (dict): The dict that contains the headers & traversal information.
        rowcount (FileLineInfo, optional): Keeps track of the number of rows (i.e., # of lines in file - 1). Defaults to None.
        prog_status (ProgramStatus, optional): Outputs the current progress of this function. Defaults to None.

    Raises:
        IOError: Raised if the file has issues with not exisiting, permissions, invalid file mode,
                 unicode encode error, or existing as a directory.
    """
    entry_ind = 1
    for entry in data:
        if prog_status:
            prog_status.update_progress_bar(f'{f"Processing data...({entry_ind})":{PADDING_WIDTH}}')
            entry_ind += 1
        row = ""
        for header in headers.values():
            if rowcount and header[0] == "null":
                row += str(rowcount.get_count()) + ","
                rowcount.increm_count()
            else:
                element = search_nested_value(entry,header)
                if element:
                    element = str(element)
                    if element.isnumeric() or re.match(r'^[-+]?\d*\.\d*$',element) is not None:
                        row += element[:-2] if element.endswith(".0") else element
                    else:
                        element = element.strip()
                        if re.search(r'\\"|\"',element):
                            element = re.sub(r'\\"|\"', "\'", element).replace("\t","\\t").replace("\n","\\n")
                        
                        row += f'\"{element}\"'
                        
                row += ","

        try:
            file.write(row[:-1]+"\n")
        except (FileNotFoundError,
                PermissionError,
                ValueError,
                UnicodeEncodeError,
                IsADirectoryError):
            raise IOError("There was an issue with this file.")


def search_nested_value(data: list, args: list) -> str|None:
    """Traverses the data provided by :func:`write_json_data_tofile` which contains
       a list of data objects given from the JSON API response of :func:`call_nvd_api`

    Args:
        data (list): The list of data that contains objects.
        args (list): The dict that contains the headers & traversal information.

    Returns:
        str|None: 
    """
    item = data

    for arg in args:
        
        try:
            usable_arg = arg
            if str(arg).isnumeric():
                usable_arg = int(arg)
            item = item[usable_arg]                
        except (KeyError, IndexError, TypeError):
            return None
    
    return item

def conduct_create_map(output_filename: str = "output.txt", 
                       start_year: int = 1988, 
                       end_year: int = CURRENT_YEAR,
                       output_mode: str = "txt",
                       limit = 0,
                       extra_args: str = "") -> None:
    """ Conducts the main 'create' operation that writes API response info to the output file.
        Processes the data map traversals specifically to be used with :func:`conduct_gather`

    Args:
        output_filename (str, optional): the file name of the output file. Defaults to "output.txt".
        start_year (int, optional): Starting published year to gather data (inclusive). Defaults to 1988.
        end_year (int, optional): Ending published year to gather data (inclusive). Defaults to CURRENT_YEAR.
        output_mode (str, optional): The given output mode to decide output format. Defaults to "txt".
        limit (int, optional): Limiting the amount of traversals outputted. Defaults to 0.
        extra_args (str, optional): Extra arguments that be given to the API. Defaults to "".
    """

    try:
        total_iter = ((end_year - start_year + 1) * 12)

        prog_status = ProgramStatus(total_iter)
        prog_status.create_progress_bar()

        api_key_exists = False
        if os.environ.get("api_key"):
            api_key_exists = True

        data_to_map = None
        largest_result_len = -1

        for month, year in iterate_month_year(start_year,end_year,throttle=3):
            prog_status.update_progress_bar(f'{"Retrieving data...":{PADDING_WIDTH}}',f'mo {month}, yr {year}',True)

            api_results = nvd_api_gather(year,month,extra_args,api_key_exists,prog_status)
            entry_info = retrieve_largest_entry(api_results,prog_status)

            if entry_info["result_length"] > largest_result_len:
                largest_result_len = entry_info["result_length"]
                data_to_map = entry_info["result"]
            

        write_api_mapping_tofile(output_filename,data_to_map,output_mode,limit)
        prog_status.update_progress_bar(f'{"Written to file. ":{PADDING_WIDTH}}')

    except IOError:
        graceful_exit(1,prog_status)
    except Exception:
        graceful_exit(prog_status=prog_status)


def retrieve_largest_entry(data_list: list, prog_status: ProgramStatus = None) -> dict[str,any]:
    """ Goes through a list of data, given they're all JSON objects.
        :func:`nvd_api_gather` Returns the appropriate data type of this.

    Args:
        data_list (list): The data list to be parsed and traversed.
        prog_status (ProgramStatus, optional): Outputs the current progress of this function. Defaults to None.

    Returns:
        dict[str,any]: Returns a dict with the fields "result" and "result_length".
    """
    
    largest_entry_len = -1
    result_entry = None
    
    for data in data_list:
        for i in range(len(data["vulnerabilities"])):
            if prog_status:
                prog_status.update_progress_bar(f'{f"Processing data...({i})":{PADDING_WIDTH}}')

            parsed_traversal_count = data_mapping.traverse_json(data["vulnerabilities"][i]).count("\n")
            if parsed_traversal_count > largest_entry_len:
                largest_entry_len = parsed_traversal_count
                result_entry = data["vulnerabilities"][i]
    
    return {
        "result":result_entry,
        "result_length":largest_entry_len
    }

def write_api_mapping_tofile(output_filename: str,
                        data_entry: any,
                        output_mode: str,
                        limit: int = 0) -> None:
    """Writes API mapping to a file given the arguments.
       `limit` denotes the number of content lines in the output.

    Args:
        output_filename (str): Output file name.
        data_entry (any): The data to be written into the output file.
        output_mode (str): The mode in which to write the file output.
        limit (int, optional): Limits the number of traversal lines. Defaults to 0.
    """
    
    
    json_out = False
    if output_mode == "json":
        json_out = True

    with open(output_filename, "w",encoding="UTF-8") as output_f:
        output_f.write(data_mapping.create_mapping(data_entry,json_out=json_out,limit=limit))


def iterate_month_year(start_year: int = 1988, end_year: int = CURRENT_YEAR, throttle: int = 0):
    """A generator that creates iterations based on every month of the given years. 
       Can be throttled every year.

    Args:
        start_year (int, optional): The start year of generator. Defaults to 1988.
        end_year (int, optional): The end year of generator. Defaults to CURRENT_YEAR.
        throttle (int, optional): Throttles based on number of seconds. Defaults to 0.

    Yields:
        Generator: returns the generator based on the given arguments.
    """

    for year_ind in range(start_year, end_year + 1):
        for month_ind in range(1,13):  
            yield month_ind, year_ind
        if throttle:
            time.sleep(throttle)

def nvd_api_gather(year_ind: int,
                month_ind: int,
                extra_args: str = "",
                api_key_exists: bool = False,
                prog_status: ProgramStatus = None) -> list:
    """Gathers the data provided by :func:`call_nvd_api` and puts the data
       into a list to be processed later. This is done specifically for the
       nvd api because it only returns things in chunks of 2000 entries.

    Args:
        year_ind (int): Year published.
        month_ind (int): Month published.
        extra_args (str, optional): Any arguments included in the URL. Defaults to "".
        api_key_exists (bool, optional): Uses API key if exists. Defaults to False.
        prog_status (ProgramStatus, optional): Outputs the current status of the API gather. Defaults to None.

    Returns:
        list: A list of the given results from the API call.
    """

    start_index = 0
    within_valid_range = True

    data_list = list()
    while within_valid_range:
        api_response = call_nvd_api(year_ind,
                                    month_ind,
                                    start_index,
                                    extra_args,
                                    api_key_exists,
                                    prog_status)
        
        if api_response is None:
            graceful_exit(0,prog_status)

        if prog_status:
            prog_status.update_progress_bar(f'{f"Organizing data...({start_index})":{PADDING_WIDTH}}')

        data = json.loads(api_response)
        data_list.append(data)
        start_index += 2000
        totalResults = data["totalResults"]

        if start_index >= totalResults :
            within_valid_range = False

    return data_list

def call_nvd_api(year: int, month: int, start_index: int, args: str = "", api_key_exists: bool = False, prog_status: ProgramStatus = None) -> str|None:
    """Calls the NVD API and returns information about the provided month in a year.

    Args:
        year (int): Year published
        month (int): Month published
        start_index (int): Beginning index of call (increments of 2000 for this API)
        args (str, optional): Any arguments included in the URL. Defaults to "".
        api_key_exists (bool, optional): Uses API key if exists. Defaults to False.
        prog_status (ProgramStatus, optional): Outputs the current status of the requests 
                                          and displays it to the progress bar if present.
                                          Defaults to None.

    Returns:
        str|None: A valid JSON string, else None is returned.
    """

    data = None

    is_not_OK = True
    attempt_counter = 0
    month_rjustified = str(month).rjust(2,'0')
    days_in_month = monthrange(year, month)[1]

    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0/?{args}pubStartDate={year}-{month_rjustified}-01T00:00:00&pubEndDate={year}-{month_rjustified}-{days_in_month}T23:59:59&resultsPerPage=2000&startIndex={start_index}'
    headers = dict()

    if api_key_exists:
        headers = {
            "apiKey" : os.environ.get("api_key")
        }

    while is_not_OK:

        try:
            with requests.get(url=url,headers=headers,allow_redirects=False) as response:
                data = response.text

                if response.status_code == 403:
                    # wait 30 seconds before calling API again

                    if prog_status:
                        for i in range(30, -1, -1):
                            status_msg = f'Waiting for API ({i}s)'
                            prog_status.update_progress_bar(status=f'{status_msg:{PADDING_WIDTH}}')
                            time.sleep(1)
                    else:
                        print("Waiting for API...") 
                        time.sleep(31)
                elif response.status_code == 200:
                    is_not_OK = False
                else:

                    if prog_status:
                        status_msg = f'Code: {response.status_code}, Trying again ({attempt_counter})'
                        prog_status.update_progress_bar(status=f'{status_msg:{PADDING_WIDTH}}')
                    else:
                        print(f'Status Code: {response.status_code}')
                        print("Processing another request...")
                    time.sleep(2)

                    attempt_counter += 1
                    if attempt_counter > 10: #limiting attempts to 10
                        
                        if prog_status:
                            prog_status.update_progress_bar(status=f'{"Exceeded attempts, aborting.":{PADDING_WIDTH}}')
                        else:
                            print("Exceeded attempts, aborting...")

                        return None
        except requests.exceptions.RequestException:
            return None

    return data

def graceful_exit(exit_status: int = -1, prog_status: ProgramStatus = None) -> None:
    """Gracefully exits the program given an exit status during operation

    Args:
        exit_status (int, optional): Denotes what caused the exit. Defaults to -1.
        prog_status (ProgramStatus, optional): Used to safely close the progress bar.
    """
    if prog_status:
        prog_status._close_progress_bar()

    if exit_status == 99: # Anything that does not require an exit message.
        print("\n")
    elif exit_status == 0: #call_nvd_api() returned None 
        print("\nThere was an issue with the API call, exiting.")
    elif exit_status == 1: #IO issue
        print("\nThere was an issue with Input/Output, exiting.")
    else:
        print("\nThere was an issue with main operation, exiting.")

    sys.exit(1)


# main function definition
def main():
    """The main operations of the script, deals with command-line arguments and
       calling the function :func:`conduct_gather` to begin the scripting process.
    """
    # command-line information
    desc = "A script that accesses the NVD NIST CVE API. Returns data of CVE entries " \
           "on a per month basis given a specified start and end year (inclusive). The " \
           "script will write the following information in a CSV format to the output " \
           "file; however, the file extension for this file does not matter."
    parser = argparse.ArgumentParser(description=desc)
    data_map_group = parser.add_mutually_exclusive_group(required=True)
    # create_map_group = data_map_group.add_argument_group()

    # output file
    parser.add_argument("-o", "--output_file", help="Where the data will be sent to.", required=True)

    # start year
    syhelp = f'Beginning published year (inclusive). Range of years: 1988 - {CURRENT_YEAR}, ' \
             "NOTE that it must be less than or equal to the end year."
    parser.add_argument("-sy", "--start_year", help=syhelp, required=True, type=CliArgValidation.validate_year)

    # end year
    eyhelp = f'Ending published year (inclusive). Range of years: 1988 - {CURRENT_YEAR}, ' \
             "NOTE that it must be greater than or equal to the start year."
    parser.add_argument("-ey", "--end_year", help=eyhelp, required=True, type=CliArgValidation.validate_year)

    # data mapping
    dmhelp = "A file containing CSV Header information for headers & data mapping for traversal. Provide either a json or txt file."
    data_map_group.add_argument("-dm", "--data_mapping", help=dmhelp, type=CliArgValidation.validate_data_map)

    cmhelp = "A setting that a user can select instead of -dm (--data_mapping) where a mapping is " \
             "created using the arguments, returning the largest number of mappings within the given" \
             " data. The -o (--output_file) option is utilized for output of the generated headers and data maps for traversal."
    data_map_group.add_argument("-cm", "--create_mapping", help=cmhelp, type=CliArgValidation.validate_create_mapping)
    
    lmhelp = "Limit the number mappings generated with a range of 1 - 100,000. Only usable when -cm (--create_mapping) is chosen."
    parser.add_argument("-lm","--limit_mapping",help=lmhelp,type=CliArgValidation.validate_limit_mapping,required=False,default=0)

    # extra arguments
    eahelp = "Extra arguments for the API URL, provide as many as needed. " \
             "Example: ... -ea arg1 arg2 arg3 ..."
    parser.add_argument("-ea", "--extra_args", nargs="+", help=eahelp,type=CliArgValidation.validate_extra_args, required=False)

    args = parser.parse_args()

    #post argument parse processing
    if args.start_year > args.end_year:
        parser.error("Please make sure that start year is less than or equal to end year (inclusve).")

    if args.data_mapping and args.limit_mapping:
        parser.error("Please make sure to not use -dm (--data_mapping) and -lm (--limit_mapping) at the same time.")
    
    eargs = ""
    if args.extra_args:
        eargs = "&".join(args.extra_args)
        eargs += "&"


    #main operation
    if args.data_mapping:
        conduct_gather(args.output_file,args.start_year,args.end_year,args.data_mapping,eargs)
    elif args.create_mapping:
        conduct_create_map(args.output_file,args.start_year,args.end_year,args.create_mapping,args.limit_mapping,eargs)
    

if __name__ == "__main__":
    main()