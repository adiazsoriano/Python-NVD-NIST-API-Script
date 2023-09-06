"""
nvd_nist_cve_gatherdata.py

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
from calendar import monthrange
from dotenv import load_dotenv
from io import TextIOWrapper

class FileLineInfo:
    """ This class keeps track of the number of lines during operation.

        Fields:
            count (int): The line counter of a file.
        
        Functions:
            increm_count(): Increments count by 1.
            get_count(): Returns count.
    """
    def __init__(self):
        self.count = 0
    
    def increm_count(self):
        self.count += 1
    
    def get_count(self):
        return self.count


def main():
    """The main operations of the script, deals with command-line arguments and
       calling the function :meth:`conduct_gather` to begin the scripting process.
    """
    # command-line information
    desc = "A script that accesses the NVD NIST CVE API. Returns data of CVE entries " \
           "on a per month basis given a specified start and end year (inclusive). The " \
           "script will write the following information in a CSV format to the output " \
           "file; however, the file extension for this file does not matter."
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument("-o", "--output_file", help="Where the data will be sent to.", required=True)
    syhelp = "Beginning published year (inclusive). Range of years: 1988 - 2023, " \
             "NOTE that it must be less than or equal to the end year."
    parser.add_argument("-sy", "--start_year", help=syhelp, required=True, type=validate_year)
    eyhelp = "Ending published year (inclusive). Range of years: 1988 - 2023, " \
             "NOTE that it must be greater than or equal to the start year."
    parser.add_argument("-ey", "--end_year", help=eyhelp, required=True, type=validate_year)
    parser.add_argument("-ch", "--csv_headers", help="CSV Header information for headers & traversal.", required=True, type=validate_csv_headers)
    eahelp = "Extra arguments for the API URL, provide as many as needed. " \
             "Example: ... -ea arg1 arg2 arg3 ..."
    parser.add_argument("-ea", "--extra_args", nargs="+", help=eahelp,type=validate_extra_args, required=False)

    args = parser.parse_args()

    #post argument parse processing
    if args.start_year > args.end_year:
        parser.print_usage()
        print("Argument Error: Please make sure that start year is less than or equal to end year (inclusve).")
        graceful_exit(99)
    
    eargs = ""
    if args.extra_args:
        eargs = "&".join(args.extra_args)
        if len(args.extra_args) == 1:
            eargs += "&"


    #main operation
    conduct_gather(args.output_file,args.start_year,args.end_year,args.csv_headers,eargs)


def validate_year(value) -> int:
    """Validates the year given a string value. This is used  in conjuction
       with argparse's :meth:`add_argument` function as "type."

    Args:
        value (any): Value passed in for validation.

    Raises:
        argparse.ArgumentTypeError: Raised if the year is not within the 1988 - 2023 range.
                                    Raised if there is a ValueError as a result of non-numeric
                                    input.

    Returns:
        int: A valid "year" value.
    """
    try:
        year = int(value)

        if year < 1988 or year > 2023:
            raise argparse.ArgumentTypeError("Please keep this within range of 1988 - 2023 (inclusive).")

        return year
    except ValueError:
        raise argparse.ArgumentTypeError("Please enter a proper non-negative real number.")


def validate_csv_headers(value) -> str:
    """Validates the given value (which is a filename) to see whether the
       contents are within the format of:
            [CSV_HEADER]:[DATA],[DATA],...,[DATA]
        This follows a loose definition of the given format, and does not
        include the content, merely the format. There may be cases where
        specific formats can cause an issue.

    Args:
        value (any): Value passed in for validation.

    Raises:
        argparse.ArgumentTypeError: Raised if the given filename isn't an actual file.
                                    Raised if the file is empty.
                                    Raised if the specific format is not followed.

    Returns:
        str: A valid filename with valid contents.
    """
    try:
        with open(str(value), "r") as csv_header_file:

            #checking for potential file empty
            if not csv_header_file.read().strip():
                raise argparse.ArgumentTypeError("Please make sure the file has content.")
            csv_header_file.seek(0)
            
            #loosely checking for content format
            for line in csv_header_file:
                if not re.match(r'^[A-Za-z0-9#_]+:[A-Za-z0-9]+(?:,[A-Za-z0-9]+)*$',line):
                    raise argparse.ArgumentTypeError(f'Please configure \"{value}\" in ' \
                                                     'the following format per line: [CSV_HEADER]:[DATA],[DATA],...,[DATA]')
            
        return str(value)
    except FileNotFoundError:
        raise argparse.ArgumentTypeError("This file does not exist, please enter a file that exists.")
    
def validate_extra_args(value) -> str:
    """Validates the extra args to make sure that they include only the characters
       specified in the URL arguments.

    Args:
        value (any): A value to be validated.

    Raises:
        argparse.ArgumentTypeError: Raised if there are any extra characters not specified.

    Returns:
        str: A valid string, not based on content but characters.
    """

    value = str(value).strip()
    
    if not re.match(r'^[\w*:/=-]+$',value):
        raise argparse.ArgumentTypeError("Please make sure to enter a proper argument for the API URL. ")
    
    return value


def conduct_gather(output_filename: str = "output.csv", 
                   start_year: int = 1988, 
                   end_year: int = 2023,
                   headers_filename: str = "csvHeaders.txt",
                   extra_args: str = ""
                   ) -> None:
    """Conducts the main 'gather' operation that writes API response info to the output file

    Args:
        output_filename (str, optional): The file name to the output file. Defaults to "output.csv".
        start_year (int, optional): Starting published year to gather data (inclusive). Defaults to 1988.
        end_year (int, optional): Ending published year to gather data (inclusive). Defaults to 2023.
        headers_filename (str, optional): The infomation needed to parse through JSON tree-structure. Defaults to "csvHeaders.txt".
        extra_args (str, optional): Extra arguments that be given to the API. Defaults to "".
    """

    try:
        with open(output_filename, "w") as output_f:

            rowcount = FileLineInfo()

            api_key_exists = False
            if os.environ.get("api_key"):
                api_key_exists = True

            json_tree_info = None
            with open(headers_filename, "r") as input_headers_f:
                json_tree_info = read_json_tree_info(input_headers_f)
            
            write_csv_headers_tofile(output_f, json_tree_info)
            rowcount.increm_count()

            for year_ind in range(start_year, end_year + 1):
                for month_ind in range(1,13):
                    data_to_write = None
                    start_index = 0
                    within_valid_range = True

                    print(f'Current year: {year_ind}, month: {month_ind}')

                    while within_valid_range:
                        api_response = call_nvd_api(year_ind,
                                                    month_ind,
                                                    start_index,
                                                    extra_args,
                                                    api_key_exists)
                        
                        if api_response is None:
                            graceful_exit(0)
                        
                        data_to_write = json.loads(api_response)
                        write_json_data_tofile(output_f, data_to_write["vulnerabilities"],json_tree_info,rowcount)
                        start_index += 2000

                        if(start_index >= data_to_write["totalResults"]):
                            within_valid_range = False
                print("- - -")
                time.sleep(2)

    except IOError:
        graceful_exit(1)    
                    

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
        :meth:`read_json_tree_info` creates a dictionary with this format.

    Args:
        file (TextIOWrapper): The file to be written to.
        headers (dict): The dict that contains the headers.
    """
    output_header = ""

    for header in headers.keys():
        output_header += header + ","
    
    file.write(output_header[:-1] + "\n")

def call_nvd_api(year: int, month: int, start_index: int, args: str = "", api_key_exists: bool = False) -> str|None:
    """Calls the NVD API and returns information about the provided month in a year.

    Args:
        year (int): Year published
        month (int): Month published
        start_index (int): Beginning index of call (increments of 2000 for this API)
        args (str, optional): Any arguments included in the URL. Defaults to "".
        api_key_exists (bool, optional): Uses API key if exists. Defaults to False.

    Returns:
        str|None: A valid JSON string, else None is returned.
    """

    data = None

    is_not_OK = True
    attempt_counter = 0
    month_rjustified = str(month).rjust(2,'0')
    days_in_month = monthrange(year, month)[1]

    while is_not_OK:
        url = f'https://services.nvd.nist.gov/rest/json/cves/2.0/?{args}pubStartDate={year}-{month_rjustified}-01T00:00:00&pubEndDate={year}-{month_rjustified}-{days_in_month}T23:59:59&resultsPerPage=2000&startIndex={start_index}'
        headers = dict()

        if api_key_exists:
            headers = {
                "apiKey" : os.environ.get("api_key")
            }

        try:
            with requests.get(url=url,headers=headers,allow_redirects=False) as response:
                data = response.text

                if response.status_code == 403:
                    # wait 30 seconds before calling API again
                    print("Waiting for API...")
                    time.sleep(31)
                elif response.status_code == 200:
                    is_not_OK = False
                else:
                    print(f'Current Status: {response.status_code}')
                    print("Processing another request...")
                    time.sleep(2)

                    attempt_counter += 1
                    if attempt_counter > 10: #limiting attempts to 10
                        print("Exceeded attempts, aborting...")
                        return None
        except Exception as e:
            return None

    return data

def write_json_data_tofile(file: TextIOWrapper, data: list, headers: dict, rowcount: FileLineInfo) -> None:
    """Writes the json data provided by the :meth:`call_nvd_api` function and 
       formated by :meth:`json.loads` function. The function is intended to
       work with the "vulnerabilities" list of the json response of the 
       NVD NIST CVE API. 

    Args:
        file (TextIOWrapper): The file to be written to.
        data (list): The list of data that contains objects.
        headers (dict): The dict that contains the headers & traversal information.
        rowcount (FileLineInfo): Keeps track of the number of rows (i.e., # of lines in file - 1).
    """

    for entry in data:
        row = ""
        for header in headers.values():
            if header[0] == "null":
                row += str(rowcount.get_count()) + ","
                rowcount.increm_count()
            else:
                element = search_nested_value(entry,header)
                if element:
                    element = str(element)
                    if element.isnumeric() or re.match(r'^[-+]?\d*\.\d*$',element) is not None:
                        row += element[:-2] if element.endswith(".0") else element
                    else:
                        row += f'\"{element}\"'
                row += ","
        file.write(row[:-1]+"\n")


def search_nested_value(data: list, args: list) -> str|None:
    """Traverses the data provided by :meth:`write_json_data_tofile` which contains
       a list of data objects given from the JSON API response of :meth:`call_nvd_api`

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
        except (KeyError, IndexError) as e:
            return None
    
    return item


def graceful_exit(exit_status: int = -1):
    """Gracefully exits the program given an exit status during operation

    Args:
        exit_status (int, optional): Denotes what caused the exit. Defaults to -1.
    """
    if exit_status == 99: # Anything that does not require an exit message.
        print("\n")
    elif exit_status == 0: #call_nvd_api() returned None 
        print("There was an issue with the API call, exiting.")
    elif exit_status == 1: #IO issue
        print("There was an issue with Input/Output, exiting.")
    else:
        print("Unknown cause of error, exiting.")

    sys.exit(1)


load_dotenv() #loads variables from the .env file
    

if __name__ == "__main__":
    main()