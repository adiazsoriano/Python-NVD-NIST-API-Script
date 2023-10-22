# Example Output
This is an example of the output that comes from the script, using the following commands.
**NOTE**: These command was done in the parent directory, shown here as an example.

## Basic usage
This is using a premade [traversal file](../csvHeaders.json).
```shell
python nvd_nist_cve_gatherdata.py -o example.csv -sy 2021 -ey 2021 -dm csvHeaders.json
```
[Result](example.csv)

## Creating and then using usage
This is an example of the output of creating a data map for the script to use, using the following command.
```shell
python nvd_nist_cve_gatherdata.py -o example_headers.json -sy 2021 -ey 2021 -cm json -lm 25
```
[Result](example_headers.json)

```shell
python nvd_nist_cve_gatherdata.py -o example2.csv -sy 2020 -ey 2020 -dm example_headers.json
```
[Result](example2.csv)