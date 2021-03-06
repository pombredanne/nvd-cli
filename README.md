# nvd-cli

**NOTE: This project is currently in BETA.. please stand by...**

This project is designed to assist with searching the National Vulnerability Database 
([NVD](https://nvd.nist.gov/)) and getting vulnerability info for the products that matter to **you**

If there's errors or anything like that, feel free to put up and issue or contact me personally.
This is a personal project of sorts but I know how useful it can be

Please be patient since this will be the first npm cli-type project I've worked on. I'll be testing as I can


## Installation

You can install this cli program via npm:

```
npm install -g nvd-cli
```

## Usage

```
$ nvd-cli --help

Usage: nvd-cli <primary flag> <primary flag arg> [optional flags]

-f, --full            Conduct a full search against the default or provided 
                      checklist for a given <year> arg

-r, --recent, recent  Search for vulnerabilaties in the NVD recent category using default 
                      or provided checklist

-s, --search          Specifically search for an NVD vulnerability matching the providded 
                      <product> or <vendor> string and optional <year> arg

- OPTIONAL PARAMETERS -

-o, --output          Change the nvd-cli output file name and/or location

-c, --checklist       Change the nvd-cli checklist file name and/or location

-t, --type            Change the output type for the NVD report (.pdf or .txt)

- MISC PARAMETERS -

-h, --help, help      Display this help text or try -h <command>

-v, --version         Get the version of nvd-cli you are currently running


For more help on a specific command/arg type help <command> without the '-' or '--'

```

**More Info on Commands:**


**Recent Check:**
```
    Usage: -r, --recent, recent, [optional parameters]

    Description:        Get RECENT NVD data matching the default or provided
                        checklist and write the report to a file
```

**Full Check:**
```
    Usage: -f, --full, <year to fully search> [optional parameters]
    
    Description:        Get FULL NVD data for a given year matching the 
                        default or provided checklist and write the report to a file
```


**Search by Product or Vendor:**
```
    Usage: -s, --search, <year to search> --product=<product_name> OR --vendor=<vendor_name> [optional parameters]
        
    Description:        Get NVD data for a given year that matches the 
                        <product_name> or <vendor_name> string
```

**Checklist Location (Optional):**
```
    Usage: <primary flag> -c, --checklist=<checklist_file_location>
            
    Description:        Specify a custom checklist other than the
                        default './checklist.json'
```

**Output Location (Optional):**
```
    Usage: <primary flag> -o, --output=<custom_output_dir/file_name>
                
    Description:        Specify a report location and file name other
                        than the default './report.pdf'
```

**Type of Output (Optional):**
```
    Usage: <primary flag> -t, --type=<file_type_to_generate ('.txt') ('.pdf')>
                    
    Description:        Change the report type to be either .txt or .pdf
```


## Configuring

TODO: Add configuration info

## Checklist Schema

**NOTE: The default checklist.json is just used for testing!!**

When providing a checklist, the .json file should look something like this:

```

[
    {
        "manufacturerName": "nodejs",
        "softwareName": "node.js"
    },
    {
        "manufacturerName": "microsoft",
        "softwareName": "windows_xp"
    },
    {
        "manufacturerName": "redhat",
        "softwareName": "enterprise_linux"
    }
]

```

## History

- **0.5.0**
    - Added `--vendor` option to `-s` and `--search` primary flags
    - Cleaned up the documentation so it made a bit more sense after some feedback
    - Minor fixes


- **0.4.9**
    - Set PDKit to default font to avoid issues

- **0.4.8**
    - Fixed checklist issue that popped up that testing didn't catch

- **0.4.7**
    - `--search` command now actually does something (accidentally left code commented when testing)


- **0.4.5**
    - Updated some legacy code involving checklist files that was causing issues if it was not found
    - Minor changes


- **0.4.1**
    - Fixed the npm install issue


- **0.4.0**
    - Added the `help <command>` functionality. There's likely typos/errors. If you find any let me know
    - Updated the `-h (--help)` information
    - Project is now up on `npm`


- **0.3.5**
    - Added the `-t (--type)` optional flag for changing the output type
    - Changed the arg validations slightly, reducing the number of pre-run checks


- **0.3.2**
    - Updated help info to be actually useful


- **0.3.1**
    - `-s` now requires at least 3 characters to search by
    - fixed HUGE issue where `-s` flag wasn't actually searching the passed year


- **0.3.0**
    - `-s` functionality has been (mostly) implimented
    - `-v` flag will now show the version of nvd-cli installed
    - Major improvment to code layout
    - Much more validation has been put in place


- **0.2.0**
    - A new (better) argument handler is now in place
    - `-f` and `-r` args work as before if not better than before
    - `-c` and `-o` commands for setting a custom checklist and output location have been added


- **0.1.2**
    - Added help command/arg handler.  `help <command>` not yet working


- **0.1.0**
    - -r and -f functionality are partially implimented


- **0.0.1**
    - Initial minimum viable product


## License

See LICENSE file in the root directory
