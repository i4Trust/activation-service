class TokenException(Exception):

    def __init__(self, message, internal_msg, status_code):
        super().__init__(message)
            
        self.status_code = status_code
        self.internal_msg = internal_msg
        self.public_msg = message

        if not internal_msg:
            self.internal_msg = message
