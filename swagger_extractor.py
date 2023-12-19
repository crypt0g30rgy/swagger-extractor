import argparse
import json
from time import time

def format_endpoint(path):
    return f"{path}"

def extract_endpoints(swagger_json):
    try:
        with open(swagger_json, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print(f"Error: File '{swagger_json}' not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: Unable to parse JSON in '{swagger_json}'.")
        return

    paths = data.get('paths', [])

    output_file_path = f"endpoints_{int(time())}.txt"
    with open(output_file_path, 'w') as output:
        for path, _ in paths.items():
            formatted_path = format_endpoint(path)
            output.write(f"{formatted_path}\n")

    print(f"Endpoints saved to '{output_file_path}'.")

def extract_all(swagger_json):
    try:
        with open(swagger_json, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print(f"Error: File '{swagger_json}' not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: Unable to parse JSON in '{swagger_json}'.")
        return

    paths = data.get('paths', {})

    output_file_path = f"all_info_{int(time())}.txt"
    with open(output_file_path, 'w') as output:
        for path, methods in paths.items():
            for method, _ in methods.items():
                formatted_path = format_endpoint(path)
                output.write(f"Method: {method}\n")
                output.write(f"{formatted_path}\n\n")

    print(f"All information saved to '{output_file_path}'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract endpoints or all information from a Swagger JSON file.")
    parser.add_argument("-f", "--file", required=True, help="Path to the Swagger JSON file.")
    parser.add_argument("-e", "--endpoints", action="store_true", help="Extract only endpoints.")
    parser.add_argument("-a", "--all", action="store_true", help="Extract all endpoint methods and paths.")
    args = parser.parse_args()

    if args.endpoints and not args.all:
        extract_endpoints(args.file)
    elif args.all and not args.endpoints:
        extract_all(args.file)
    else:
        print("Error: Please specify either '-e' for endpoints or '-a' for all information.")