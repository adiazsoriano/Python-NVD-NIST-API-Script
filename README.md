# Python-NVD-NIST-API-Script
The python version of: [PHP-NVD-NIST-API-script](https://github.com/adiazsoriano/PHP-NVD-NIST-API-script). It is a CLI based script that takes in command-line arguments. This version may contain improvements over the PHP counterpart.

## The .env file
The script reads from the .env file inside the folder if present. Or it reads from the environment using the OS module. Otherwise it defaults to not having an api key. Check [here](.env) for an example of this.
```dotenv
api_key='API KEY GOES HERE'
```

## Output modes
The script can output data retrieved and stored in a CSV format. The script can also take that same data (grabs the entry with the most traversals) and turn the data into traversals that can be used to then retrieve specific data. These are the "data_mapping" and "create_mapping" modes respectively. 

## Usage
General usage of the script and the needed arguments.
```
usage: nvd_nist_cve_gatherdata.py [-h] -o OUTPUT_FILE -sy START_YEAR -ey END_YEAR
                                  (-dm DATA_MAPPING | -cm CREATE_MAPPING) [-lm LIMIT_MAPPING]
                                  [-ea EXTRA_ARGS [EXTRA_ARGS ...]]

A script that accesses the NVD NIST CVE API. Returns data of CVE entries on a per month basis given a specified start
and end year (inclusive). The script will write the following information in a CSV format to the output file; however,
the file extension for this file does not matter.

options:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output_file OUTPUT_FILE
                        Where the data will be sent to.
  -sy START_YEAR, --start_year START_YEAR
                        Beginning published year (inclusive). Range of years: 1988 - 2023, NOTE that it must be less
                        than or equal to the end year.
  -ey END_YEAR, --end_year END_YEAR
                        Ending published year (inclusive). Range of years: 1988 - 2023, NOTE that it must be greater
                        than or equal to the start year.
  -dm DATA_MAPPING, --data_mapping DATA_MAPPING
                        A file containing CSV Header information for headers & data mapping for traversal. Provide
                        either a json or txt file.
  -cm CREATE_MAPPING, --create_mapping CREATE_MAPPING
                        A setting that a user can select instead of -dm (--data_mapping) where a mapping is created
                        using the arguments, returning the largest number of mappings within the given data. The -o
                        (--output_file) option is utilized for output of the generated headers and data maps for
                        traversal.
  -lm LIMIT_MAPPING, --limit_mapping LIMIT_MAPPING
                        Limit the number mappings generated with a range of 1 - 100,000. Only usable when -cm
                        (--create_mapping) is chosen.
  -ea EXTRA_ARGS [EXTRA_ARGS ...], --extra_args EXTRA_ARGS [EXTRA_ARGS ...]
                        Extra arguments for the API URL, provide as many as needed. Example: ... -ea arg1 arg2 arg3
                        ...
Example:
    Example 1: General usage (all required arguments)
    >python nvd_nist_cve_gatherdata.py -o output.csv -sy 1988 -ey 2023 -dm csvHeaders.txt

    Example 2: With the optional arguments
    >python nvd_nist_cve_gatherdata.py -o options.csv -sy 2021 -ey 2021 -dm csvHeaders.json -ea noRejected cvssV2Severity=LOW

    Example 2: Creating a data map (with a limit of 100 lines)
    >python nvd_nist_cve_gatherdata.py -o traversals.json -sy 2021 -ey 2021 -cm json -lm 100
```
For more information on optional arguments, see [here](https://nvd.nist.gov/developers/vulnerabilities) under "CVE API" Parameters.

**NOTE**: The API call within the script already uses `pubStartDate`, `pubEndDate`, `resultsPerPage`, and `startIndex`.

## Extra information about the data map traversals
The following can be added into the files to include a row number if desired.
### TXT files
```
row#:null
```
### JSON files
```json
"row#": ["null"]
```

## Example Output
Check out [this folder](example_output/) to see an example of various outputs.