#!/bin/bash

# Function to generate a random number
generate_random_number() {
    echo $((1 + RANDOM % 1000))
}

# Initialize variables
file_arg=""
url_arg=""
input_stdin=false

# Set the custom template path
custom_template_path="/root/nuclei-templates/http/exposures"

# Generate a random number for the output filename
random_number=$(generate_random_number)

# Set the default output filename
output_filename="nuclei_results_secrets_${random_number}.txt"

# Set the default input filename for -i option
input_filename="/tmp/tmp_${random_number}"

# Check if URLs are piped into the script
if [ ! -t 0 ]; then
    # URLs are piped, write them to the input file
    cat > "$input_filename"
    input_stdin=true
fi

# Check command line options
while getopts ":f:u:" opt; do
    case $opt in
        f)
            file_arg="$OPTARG"
            ;;
        u)
            url_arg="$OPTARG"
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            echo "Usage: $0 [-f file] [-u URL]"
            exit 1
            ;;
    esac
done

# If URLs are not piped, check if -f or -u flag was provided
if [ ! "$input_stdin" = true ]; then
    # Check if either -f or -u flag was provided
    if [ -z "$file_arg" ] && [ -z "$url_arg" ]; then
        echo "Usage: $0 [-f file] [-u URL]"
        exit 1
    fi

    # Check if both -f and -u flags were provided (which is not allowed)
    if [ ! -z "$file_arg" ] && [ ! -z "$url_arg" ]; then
        echo "Error: Both -f and -u options cannot be provided simultaneously." >&2
        echo "Usage: $0 [-f file] [-u URL]"
        exit 1
    fi
fi

# If -f flag is provided, use it as a file argument
if [ ! -z "$file_arg" ]; then
    # Check if the file exists
    if [ ! -f "$file_arg" ]; then
        echo "File not found: $file_arg"
        exit 1
    fi
    nuclei_cmd="nuclei -l $file_arg -t $custom_template_path -o $output_filename"
elif [ ! -z "$url_arg" ]; then
    # If -u flag is provided, use it as a URL argument
    nuclei_cmd="nuclei $url_arg -t $custom_template_path -o $output_filename"
elif [ "$input_stdin" = true ]; then
    # If URLs are piped, use the input file generated from STDIN
    nuclei_cmd="nuclei -l $input_filename -t $custom_template_path -o $output_filename"
fi

# Execute the nuclei command
echo "Executing: $nuclei_cmd"
eval $nuclei_cmd

# Cleanup: Remove temporary files
rm -f "$input_filename"

