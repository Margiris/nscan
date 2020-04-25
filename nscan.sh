#!/bin/sh
# POSIX

# Reset all variables that might be set
args_output=""
args_verbose=0
args_scan_type="mini"

# # When called, the process ends.
# Args:
# 	$1: The exit message (print to stderr)
# 	$2: The exit code (default is 1)
# if env var _PRINT_HELP is set to 'yes', the usage is print to stderr (prior to $1)
# Example:
# 	test -f "$_arg_infile" || _PRINT_HELP=yes die "Can't continue, have to supply file as an argument, got '$_arg_infile'" 4
die() {
    _ret=$2
    test -n "$_ret" || _ret=1
    test "$_PRINT_HELP" = yes && print_help >&2
    echo "$1" >&2
    exit ${_ret}
}

# Function that prints general usage of the script.
# This is useful if users asks for it, or if there is an argument parsing error (unexpected / spurious arguments)
# and it makes sense to remind the user how the script is supposed to be called.
print_help() {
    printf '%s\n' "Convenient wrapper for nscan.nse network scanner script, used by nmap."
    printf 'Usage: %s [-t|--scan-type <arg>] [-o|--output <arg>] [-v|--verbose] [-h|--help] [--] <interface-1> [<interface-2>] ... [<interface-n>] ...\n' "$0"
    printf '\t%s\n' "<interface>: Interfaces to scan on."
    printf '\t%s\n' "-t, --scan-type: Type of scan to perform. Accepted values: full, mini. (default: 'mini')"
    printf '\t%s\n' "-o, --output: File to write scan results to. (default: '{date and time of script's start}')"
    printf '\t%s\n' "-v, --verbose: Print diagnostic information from the script to console. Also turns on nmap's debug mode (-d). (off by default)"
    printf '\t%s\n' "-h, --help: Prints help"
}

# Check that we receive expected amount of positional arguments.
# Return 0 if everything is OK, 1 if we have too little arguments.
handle_passed_args_count() {
    _required_args_string="'interface'"
    test "${_positionals_count}" -ge 1 || _PRINT_HELP=yes die "FATAL ERROR: Not enough positional arguments - we require at least 1 (namely: $_required_args_string), but got only ${_positionals_count}." 1
}

# The parsing of the command-line
while :; do
    case $1 in
    -h | --help) # Call a "print_help" function to display a synopsis, then exit.
        print_help
        exit
        ;;

    -v | --verbose)
        args_verbose=$((args_verbose + 1)) # Each -v argument adds 1 to verbosity.
        ;;

    -o | --output) # Takes an option argument, ensuring it has been specified.
        if [ -n "$2" ]; then
            args_output=$2
            shift
        else
            printf 'ERROR: "--output" requires a non-empty option argument.\n' >&2
            exit 1
        fi
        ;;
    --output=?*)
        args_output=${1#*=} # Delete everything up to "=" and assign the remainder.
        ;;
    --output=) # Handle the case of an empty --output=
        printf 'ERROR: "--output" requires a non-empty option argument.\n' >&2
        exit 1
        ;;

    -t | --scan-type) # Takes an option argument, ensuring it has been specified.
        if [ -n "$2" ]; then
            if [ "$2" = "full" ] || [ "$2" = "mini" ]; then
                args_scan_type=$2
            else
                printf 'ERROR: Unknown "--scan-type" value: %s\n' "$2" >&2
                exit 1
            fi
            shift
        else
            printf 'ERROR: "--scan-type" requires a non-empty option argument.\n' >&2
            exit 1
        fi
        ;;
    --scan-type=?*)
        args_scan_type=${1#*=} # Delete everything up to "=" and assign the remainder.
        ;;
    --scan-type=) # Handle the case of an empty --scan-type=
        printf 'ERROR: "--scan-type" requires a non-empty option argument.\n' >&2
        exit 1
        ;;

    --) # End of all options.
        shift
        break
        ;;
    -?*)
        printf 'WARN: Unknown option (ignored): %s\n' "$1" >&2
        ;;
    *) # Default case: If no more options then break out of the loop.
        break ;;
    esac

    shift
done

# Rest of the program here.
# If there are input files (for example) that follow the options, they
# will remain in the "$@" positional parameters.

args_interfaces="$*"

echo
echo "Value of --scan-type: $args_scan_type"
echo "Value of --output: $args_output"
echo "verbose is $args_verbose"
echo "Got interfaces: $args_interfaces"
echo

mkdir /tmp/nscan

nscan_type=", nscan.type=$args_scan_type"

if [ "$args_output" != "" ]; then
    nscan_filename="nscan.filename=$args_output"
fi

if [ $args_verbose -gt 0 ]; then
    if [ "$args_output" != "" ]; then
        cat_command="&& cat $args_output"
    fi
    nscan_verbose=", nscan.v=true' -d"
else
    nscan_verbose="'"
fi

for i in $args_interfaces; do
    nscan_interface="nscan.interface=$i"

    nscan_script_args="'$nscan_filename $nscan_type $nscan_interface $nscan_verbose"

    echo "-----------------"
    echo "nscan_script_args: $nscan_script_args"
    echo "cat_command: $cat_command"
done
# nmap -n -sn -PR --send-eth --script nscan.nse --script-args $nscan_script_args $cat_command
# '$nscan_filename, nscan.interface=--list, nscan.type=mini, nscan.v=true'
