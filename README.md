# nvd-cli

**This project is currently in BETA.. please stand by...**

## Installation

You can install this cli program via npm:

```
npm install -g nvd-cli
```

**NOTE: THis project will NOT be on npm until Beta 0.4**

## Usage

```
$ nvd-cli --help

Usage: nvd-cli <primary flag> <primary flag arg> [optional flags]

-f, --full            Conduct a full search against the default or provided 
                      checklist for a given <year> arg

-r, --recent          Search for vulnerabilaties in the NVD recent category using default 
                      or provided checklist

-s, --search          Specifically search for an NVD vulnerability matching the providded 
                      <product> or <vendor> string and optional <year> arg

- OPTIONAL PARAMETERS -

-o, --output          Change the nvd-cli output file name and/or location

-c, --checklist       Change the nvd-cli checklist file name and/or location

- MISC PARAMETERS -

-h, --help, help      Display this help text or try -h <command>

-v, --version         Get the version of nvd-cli you are currently running

```

## Configuring

## Checklist Schema

## History

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
