
# This class creates our own error, it inherits from Exception class
class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message) # Pass the message to Exception 
        self.status = status
        self.code = code
        self.message = message

def bad_request(code, message): # Bit of shortcut to create a 400 error with a code and message
    return ApiError(400, code, message)