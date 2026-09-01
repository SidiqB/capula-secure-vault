import argparse
import json  # This module provides functions for working with JSON data.
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer   # First helps us respond to requests, while the second allows us to create a simple HTTP server.
from pathlib import Path
from .errors import ApiError, bad_request
from .service import VaultService
from .storage import JsonStore



MAX_REQUEST_BYTES = 256 * 1024 # Sets the maximum size of incoming requests to 256 KB.
DEFAULT_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "vault.json"


class VaultRequestHandler(BaseHTTPRequestHandler): # Using Base__ as the parent class
    service = None

    def do_GET(self):   # What the server does when it receives a GET request
        
        # Check if the request path is "/health". If not, respond with a 404 Not Found status.
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            return
        
        response = {"status": "ok"}   # Our health check response
        self.send_json(200, response)
    
    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8") # Gets the directory into JSON text and then into bytes

        # Next part says request successful, content type is JSON, and content length is the length of the body in bytes
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        # This method reads the incoming request body and attempts to parse it as JSON. It performs several checks to ensure the request is valid.
        content_type = self.headers.get("Content-Type", "")

        if not content_type.lower().startswith("application/json"):
            raise ApiError(
                415,
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type must be application/json",
            )

        content_length_values = self.headers.get_all("Content-Length", [])

        if not content_length_values:
            raise ApiError(411, "LENGTH_REQUIRED", "Content-Length is required")

        if len(content_length_values) != 1:
            raise bad_request(
                "INVALID_CONTENT_LENGTH",
                "exactly one Content-Length header is required",
            )

        try:
            content_length = int(content_length_values[0])
        except ValueError:
            raise bad_request(
                "INVALID_CONTENT_LENGTH",
                "Content-Length must be a number",
            )

        if content_length < 0:
            raise bad_request(
                "INVALID_CONTENT_LENGTH",
                "Content-Length cannot be negative",
            )

        if content_length > MAX_REQUEST_BYTES:
            raise ApiError(413, "REQUEST_TOO_LARGE", "request body is too large")

        raw_body = self.rfile.read(content_length)

        try: 
            data = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise bad_request("INVALID_JSON", "request body must contain valid JSON")

        if not isinstance(data, dict):
            raise bad_request("INVALID_JSON", "request body must be a JSON object")

        return data
    
    def send_api_error(self, error):
        # We send an API error in JSON format with the appropriate HTTP status code and error details.
        response = {
            "error": {
                "code": error.code,
                "message": error.message,
            }
        }

        self.send_json(error.status, response)
    
    def do_POST(self):
        # What to do when client sends a POST request.
        try: # We try to read the request body as JSON, handle the POST request, and send a JSON response.
            body = self.read_json()
            status, response = self.handle_post(body)
            self.send_json(status, response)

        except ApiError as error: # If an ApiError is raised, we catch it and send the error response back to the client.
            self.send_api_error(error)

        except Exception as error: # If any other unexpected error occurs, we log it and send a generic internal server error response.
            print(f"Unexpected server error: {error}")
            self.send_api_error(
                ApiError(500, "INTERNAL_ERROR", "an internal error occurred")
            )
    
    def handle_post(self, body): 
        # We route POST requests to the appropriate service method based on the request path.
        if self.path == "/v1/register":
            return self.service.register(body)
        if self.path == "/v1/verify-email":
            return self.service.verify_email(body)
        if self.path == "/v1/store":
            return self.service.store_vault(body)
        if self.path == "/v1/retrieve":
            return self.service.retrieve_vault(body)
        raise ApiError(  # We raise a 404 error if the path is not recognised.
            404,
            "NOT_FOUND",
            "API route not found",
        )

def create_server(host, port, data_path, handler_class=VaultRequestHandler):
    store = JsonStore(data_path).initialise()
    handler_class.service = VaultService(store)
    return ThreadingHTTPServer((host, port), handler_class)

# The function to start the server
def main(arguments=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--data", default=str(DEFAULT_DATA_PATH))
    options = parser.parse_args(arguments)
    host = options.host
    port = options.port
    store = JsonStore(options.data).initialise()
    VaultRequestHandler.service = VaultService(store)
    server = ThreadingHTTPServer((host, port), VaultRequestHandler)  # This creates server, first gives address it should listen and then the class that handles requests.
    actual_host, actual_port = server.server_address
    print(f"Server running at http://{actual_host}:{actual_port}")

    try:
        server.serve_forever()  # This starts the server and keeps it running indefinitely, waiting for requests.
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()  # This runs the main function when the script is executed directly.
