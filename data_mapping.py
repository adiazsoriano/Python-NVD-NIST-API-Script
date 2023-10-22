""" 
data_mapping.py


Author: Angel Diaz-Soriano
Date Created: 10/1/2023
"""

import re

def create_mapping(json_data: any, max_header_parts: int = 3, json_out = False, limit: int = 0) -> str:
    """Creates a data map traversal of the given JSON data.
        The format is as follows (for both "txt" and "json" output):
            CSV_HEADER:[TRAVERSAL...]

    Args:
        json_data (any): Any given JSON data.
        max_header_parts (int, optional): amount of parts for the header. Defaults to 3.
        json_out (bool, optional): Determines if to do JSON out. Defaults to False.
        limit (int, optional): Limits the number of lines to process and return. Defaults to 0.

    Returns:
        str: Returns a string of all of the mappings.
    """
    
    trav_str_lines = traverse_json(json_data).splitlines()
    map_str = ""

    MAX_HEADER_PARTS = max_header_parts

    current_line_ind = 0
    for line in trav_str_lines:
        header_ind = 0
        i = 0
        header = list()
        line_spl = line.strip().split("||")[:-1]
        while i < len(line) and header_ind < MAX_HEADER_PARTS:

            rev_ind = (i+1)*-1
            if (len(line_spl)*-1) < rev_ind and not re.match(r'^[0-9]+$', line_spl[rev_ind]):
                header.append(line_spl[rev_ind])
                header_ind += 1

            i += 1
        
        if json_out:
            json_list = list()
            for part in line_spl:
                json_list.append(f'\"{part}\"' if not re.match(r'^[0-9]+$', part) else part)
            line_spl = json_list

        hdr_str = "_".join(header)
        hdr_occur = map_str.count(hdr_str)
        if not json_out:
            map_str += f'{hdr_str if hdr_occur < 1 else f"{hdr_str}_{hdr_occur+1}"}:{",".join(line_spl)}\n'
        else:
            map_str += f'\t\"{hdr_str if hdr_occur < 1 else f"{hdr_str}_{hdr_occur+1}"}\":[{",".join(line_spl)}],\n'

        current_line_ind += 1
        if limit != 0 and current_line_ind >= limit:
            break

    if json_out:
        map_str = f'{{\n{map_str[:-2]}\n}}'

    return map_str.strip()


def traverse_json(json_data: any, current: str = "") -> str:
    """Traverses the given JSON based on the LIST/DICT formats of the data.
        Collects all of the traversal information in a string to return.
        Seperates each part initially by '||' to ensure that the data is
        seperated properly.

    Args:
        json_data (any): The given JSON data.
        current (str, optional): The current str value of traversal. Defaults to "".

    Returns:
        str: Returns the raw traversal information of the JSON data.
    """

    result = ""
    if isinstance(json_data,list):
        i = 0
        for item in json_data:
            result += traverse_json(item,f'{current}||{i}' if current else i)
            i += 1
    elif isinstance(json_data,dict):
        
        for key, item in json_data.items():
            result += traverse_json(item, f'{current}||{key}' if current else key)
    else:
        return (f'{current}||{str(json_data)}' if current else str(json_data))+"\n"
    
    return result