# Python-NVD-NIST-API-Script
The python version of: [PHP-NVD-NIST-API-script](https://github.com/adiazsoriano/PHP-NVD-NIST-API-script). It is a CLI based script that takes in command-line arguments. This version may contain improvements over the PHP counterpart.

## The .env file
The script reads from the .env file inside the folder if present. Or it reads from the environment using the OS module. Otherwise it defaults to not having an api key. Check [here](.env) for an example of this.
```dotenv
api_key='API KEY GOES HERE'
```

## Usage
Geneal usage of the script and the needed arguments.
```
Usage: nvd_nist_cve_gatherdata.py [-h] -o OUTPUT_FILE -sy START_YEAR -ey END_YEAR -dm DATA_MAPPING
                                  [-ea EXTRA_ARGS [EXTRA_ARGS ...]]

Description:
    A script that accesses the NVD NIST CVE API. Returns data of CVE entries on a per month basis given a specified start
    and end year (inclusive). The script will write the following information in a CSV format to the output file; however,
    the file extension for this file does not matter.

Arguments:
    -h, --help          show this help message and exit
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
    -ea EXTRA_ARGS [EXTRA_ARGS ...], --extra_args EXTRA_ARGS [EXTRA_ARGS ...]
                        Extra arguments for the API URL, provide as many as needed. Example: ... -ea arg1 arg2 arg3
                        ...
Example:
    Example 1: General usage (all required arguments)
    >python nvd_nist_cve_gatherdata.py -o output.csv -sy 1988 -ey 2023 -dm csvHeaders.txt

    Example 2: With the optional arguments
    >python nvd_nist_cve_gatherdata.py -o options.csv -sy 2021 -ey 2021 -dm csvHeaders.json -ea noRejected cvssV2Severity=LOW
```
For more information on optional arguments, see [here](https://nvd.nist.gov/developers/vulnerabilities) under "CVE API" Parameters.

**NOTE**: The API call within the script already uses `pubStartDate`, `pubEndDate`, `resultsPerPage`, and `startIndex`.

## Example Output
Check out [this folder](example_output/) to see an example of output.