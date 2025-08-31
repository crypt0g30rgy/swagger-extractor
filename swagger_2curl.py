import argparse
import json
import uuid
import base64
from time import time
from datetime import datetime, timedelta

def format_endpoint(path):
    return f"{path}"

def load_swagger(swagger_json):
    try:
        with open(swagger_json, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: File '{swagger_json}' not found.")
    except json.JSONDecodeError:
        print(f"Error: Unable to parse JSON in '{swagger_json}'.")
    return None

def generate_example_value(param_schema):
    """Return a dummy value based on schema type/format."""
    if not isinstance(param_schema, dict):
        return "example_value"

    t = param_schema.get("type")
    fmt = param_schema.get("format", "")

    if t == "integer":
        return 123
    elif t == "number":
        return 123.45
    elif t == "string":
        if fmt == "uuid":
            return str(uuid.uuid4())
        elif fmt == "date":
            return "2025-08-09"
        elif fmt == "date-time":
            return datetime.utcnow().isoformat() + "Z"
        else:
            return "example_string"
    elif t == "boolean":
        return True
    elif t == "array":
        return [generate_example_value(param_schema.get("items", {}))]
    elif t == "object":
        props = param_schema.get("properties", {})
        return {k: generate_example_value(v) for k, v in props.items()}
    return "example_value"

def generate_fake_jwt():
    """Generate a fake but valid-looking JWT token."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": str(uuid.uuid4()),
        "name": "John Doe",
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    }).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(b"signature").decode().rstrip("=")
    return f"{header}.{payload}.{signature}"

def extract_security_schemes(data):
    """Return dict of security schemes from OpenAPI components."""
    return data.get("components", {}).get("securitySchemes", {})

def get_operation_security_headers(schemes, operation_security):
    """Return headers/query params for this operation's security definition."""
    headers = []
    query_params = []

    for sec_req in operation_security:
        for scheme_name in sec_req.keys():
            scheme = schemes.get(scheme_name, {})
            stype = scheme.get("type")
            if stype == "http" and scheme.get("scheme") == "bearer":
                headers.append(f"-H 'Authorization: Bearer {generate_fake_jwt()}'")
            elif stype == "apiKey":
                location = scheme.get("in")
                key_name = scheme.get("name", "api_key")
                if location == "header":
                    headers.append(f"-H '{key_name}: example_key'")
                elif location == "query":
                    query_params.append(f"{key_name}=example_key")
    return headers, query_params

def extract_curl(swagger_json):
    data = load_swagger(swagger_json)
    if not data:
        return

    base_url = data.get("servers", [{"url": "http://localhost"}])[0]["url"]
    paths = data.get('paths', {})
    security_schemes = extract_security_schemes(data)
    global_security = data.get("security", [])  # global security requirement

    output_file_path = f"curl_examples_{int(time())}.txt"
    with open(output_file_path, 'w') as output:
        for path, methods in paths.items():
            for method, details in methods.items():
                url = f"{base_url}{path}"
                headers = ["-H 'Content-Type: application/json'"]
                query_params = []
                body_data = None

                # Determine applicable security
                operation_security = details.get("security", global_security)
                sec_headers, sec_query_params = get_operation_security_headers(security_schemes, operation_security)
                headers += sec_headers
                query_params += sec_query_params

                # Replace path params & collect query params
                for p in details.get("parameters", []):
                    if p.get("in") == "path":
                        value = generate_example_value(p.get("schema", {}))
                        url = url.replace(f"{{{p['name']}}}", str(value))
                    elif p.get("in") == "query":
                        value = generate_example_value(p.get("schema", {}))
                        query_params.append(f"{p['name']}={value}")

                if query_params:
                    url += "?" + "&".join(query_params)

                # Request body
                if "requestBody" in details:
                    content = details["requestBody"].get("content", {})
                    if "application/json" in content:
                        schema = content["application/json"].get("schema", {})
                        body_data = generate_example_value(schema)

                # Build curl
                curl_cmd = [f"curl -X {method.upper()} '{url}'"] + headers
                if body_data is not None:
                    curl_cmd.append(f"-d '{json.dumps(body_data)}'")

                output.write(" ".join(curl_cmd) + "\n\n")

    print(f"Curl examples saved to '{output_file_path}'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate curl examples from a Swagger/OpenAPI JSON file.")
    parser.add_argument("-f", "--file", required=True, help="Path to the Swagger JSON file.")
    parser.add_argument("-c", "--curl", action="store_true", help="Generate curl examples for all endpoints.")
    args = parser.parse_args()

    if args.curl:
        extract_curl(args.file)
    else:
        print("Error: Use -c to generate curl examples.")
