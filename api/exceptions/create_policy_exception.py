class CreatePolicyException(Exception):

    def __init__(self, message, status_code, internal_msg):
        super().__init__(message)
            
        self.status_code = status_code
        self.internal_msg = internal_msg
