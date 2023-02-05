import re
import json


class DataLossPrevention:
    def __init__(self, dictOfSensitiveData):

        # -----------------  START OF REGULAR EXPRESSION ---------------- #

        self.email_regex = re.compile(r'[\w\.-]+@[\w\.-]+')
        self.nric_regex = re.compile(r'[STFGstf]\d{7}[A-Za-z]')
        self.phone_regex = re.compile(r'(\+65|65|0)[ -]?\d{8}')
        self.ip_regex = re.compile(r'\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}')
        
        self.github_auth_token = re.compile(r'[0-9a-f]{40}')
        self.json_web_token = re.compile(r'ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*|ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*')
        self.creditcard = re.compile(r'\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}')

        # -----------------  END OF REGULAR EXPRESSION ---------------- #

        self.dictOfSensitiveData = json.dumps(dictOfSensitiveData)


    def detect_sensitive_data(self):
        """

        Detects sensitive data in a given piece of text using regular expressions.

        """

        email = self.email_regex.findall(self.dictOfSensitiveData)
        nric_numbers = self.nric_regex.findall(self.dictOfSensitiveData)
        phone_numbers = self.phone_regex.findall(self.dictOfSensitiveData)
        ip_addresses = self.ip_regex.findall(self.dictOfSensitiveData)
        github_auth_token = self.github_auth_token.findall(self.dictOfSensitiveData)
        json_web_token = self.json_web_token.findall(self.dictOfSensitiveData)
        creditcard = self.creditcard.findall(self.dictOfSensitiveData)

        SensitiveData = {
            "nric_numbers": nric_numbers,
            "email_addresses": email,
            "phone_numbers": phone_numbers,
            "ip_addresses": ip_addresses,
            "github_auth_token": github_auth_token,
            "json_web_token": json_web_token,
            "credit_card": creditcard
        }

        return json.dumps(SensitiveData, indent=4)


    def replace_sensitive_data(self):
        """

        Replaces sensitive data in a given piece of text using regular expressions.

        """

        self.dictOfSensitiveData = self.nric_regex.sub("[nric_protected]", self.dictOfSensitiveData)
        self.dictOfSensitiveData = self.email_regex.sub("[email_protected] ", self.dictOfSensitiveData)
        self.dictOfSensitiveData = self.phone_regex.sub("[phone_protected]", self.dictOfSensitiveData)
        self.dictOfSensitiveData = self.ip_regex.sub("[ip_protected]", self.dictOfSensitiveData)

        self.dictOfSensitiveData = self.github_auth_token.sub("[github_auth_token_protected]", self.dictOfSensitiveData)
        self.dictOfSensitiveData = self.json_web_token.sub("[json_web_token_protected]", self.dictOfSensitiveData)

        self.dictOfSensitiveData = self.creditcard.sub("[creditcard_protected]", self.dictOfSensitiveData)

        self.dictOfSensitiveData = json.loads(self.dictOfSensitiveData)

        return str(self.dictOfSensitiveData)



# if __name__ == '__main__':

#     dictOfSensitiveData = {
#             "nric_numbers": "S1234567B",
#             "email_addresses": "l@gmaol.com",
#             "phone_numbers": "+6512345678",
#             "ip_addresses": "90.65.1.1",
#             "github_auth_token": "8d151140ddfadec0b5c2c2f7bb87f902c1dc6f51",
#             "json_web_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
#             "creditcard": "4111111111111111",
#         }

#     sensitive_data = DataLossPrevention(dictOfSensitiveData)

#     sensitive_data.detect_sensitive_data()
#     print(sensitive_data.replace_sensitive_data().encode('utf-8'))
