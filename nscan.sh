#!/bin/sh
# POSIX

# Reset all variables that might be set
nscan_dir="/tmp/nscan"
args_output=""
args_verbose=0
args_scan_type="mini"
args_interface=""
nscan_type=
nscan_filename=
nscan_verbose=
cat_command=

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
    printf 'Usage: %s [-t|--scan-type <arg>] [-o|--output <arg>] [-l|--list] [-v|--verbose] [-h|--help] [--] <interface>\n' "$0"
    printf '\t%s\t%s\n' "<interface>" "Interface to scan on."
    printf '\t%s\t%s\n' "-t, --scan-type" "Type of scan to perform. Accepted values: full, mini. (default: 'mini')"
    printf '\t%s\t%s\n' "-o, --output" "File to write scan results to. (default: '{date and time of script's start}')"
    printf '\t%s\t%s\n' "-l, --list" "List interfaces available for scanning. Does not perform any scanning. (off by default)"
    printf '\t%s\t%s\n' "-v, --verbose" "Print diagnostic information from the script to console. Specifying this twice (-v -v) also turns on this script's command printing and nmap's debug mode (-d). (off by default)"
    printf '\t%s\t%s\n' "-h, --help" "Prints help"
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

    -l | --list)
        args_interface="--list" # List interfaces instead of scanning.
        ;;

    -o | --output) # Takes an option argument, ensuring it has been specified.
        test -n "$2" && test "$(printf '%s' "$2" | cut -c1)" != - || _PRINT_HELP=yes die "ERROR: '$1' requires a non-empty option argument." 1
        args_output=$2
        shift
        ;;
    --output=?*)
        args_output=${1#*=} # Delete everything up to "=" and assign the remainder.
        ;;
    --output=) # Handle the case of an empty --output=
        _PRINT_HELP=yes die "ERROR: '$1' requires a non-empty option argument." 1
        ;;

    -t | --scan-type) # Takes an option argument, ensuring it has been specified.
        test -n "$2" && test "$(printf '%s' "$2" | cut -c1)" != - || _PRINT_HELP=yes die "ERROR: '$1' requires a non-empty option argument." 1
        if [ "$2" = "full" ] || [ "$2" = "mini" ]; then
            args_scan_type=$2
        else
            _PRINT_HELP=yes die "ERROR: Unknown '--scan-type' value: '$2'" 2
        fi
        shift
        ;;
    --scan-type=?*)
        args_scan_type=${1#*=} # Delete everything up to "=" and assign the remainder.
        ;;
    --scan-type=) # Handle the case of an empty --scan-type=
        _PRINT_HELP=yes die "ERROR: '$1' requires a non-empty option argument." 1
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

# Turn on command printing if verbose was specified 3 or more times.
if [ $args_verbose -gt 2 ]; then
    set -x
fi

mkdir $nscan_dir >/dev/null 2>&1

if [ "$args_interface" = "" ]; then
    args_interface=$1
    test -n "$args_interface" && test "$args_interface" != "" || die "ERROR: No interface specified. Did you mean '$0 --list' ?" 3
fi
test "$args_output" != "" && nscan_filename=", nscan.filename=$args_output"
if [ $args_verbose -gt 0 ]; then
    test "$args_output" != "" && cat_command="&& cat $nscan_dir/$args_output"
    # Turn on nmap's debug mode if verbose was specified 2 or more times.
    test $args_verbose -gt 1 && debug_flag="-d"
    nscan_verbose=", nscan.v=true' $debug_flag"
else
    nscan_verbose="'"
fi
nscan_interface=", nscan.interface=$args_interface"
nscan_type="nscan.type=$args_scan_type"

if [ "$args_scan_type" = "full" ]; then
    eval "nmap -n -O -PR --send-eth --script nscan.nse --script-args '$nscan_type $nscan_interface $nscan_filename $nscan_verbose $cat_command"
else
    eval "nmap -n -sn -PR --send-eth --script nscan.nse --script-args '$nscan_type $nscan_interface $nscan_filename $nscan_verbose $cat_command"
fi

# Turn command printing off
set +x
