import re
import json


class DataLossPrevention:
    def __init__(self, dictOfSensitiveData):

        # -----------------  START OF REGULAR EXPRESSION ---------------- #

        self.credit_card_regex = re.compile(r'\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}')
        self.email_regex = re.compile(r'[\w\.-]+@[\w\.-]+')
        self.nric_regex = re.compile(r'[STFGstf]\d{7}[A-Za-z]')
        self.phone_regex = re.compile(r'(\+65|65|0)[ -]?\d{8}')
        self.ip_regex = re.compile(r'\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}')

        # -----------------  END OF REGULAR EXPRESSION ---------------- #

        self.dictOfSensitiveData = json.dumps(dictOfSensitiveData)


    def detect_sensitive_data(self):
        """

        Detects sensitive data in a given piece of text using regular expressions.

        """

        nric_numbers = self.nric_regex.findall(self.dictOfSensitiveData)
        credit_card_numbers = self.credit_card_regex.findall(self.dictOfSensitiveData)
        email_addresses = self.email_regex.findall(self.dictOfSensitiveData)
        phone_numbers = self.phone_regex.findall(self.dictOfSensitiveData)
        ip_addresses = self.ip_regex.findall(self.dictOfSensitiveData)

        SensitiveData = {
            "nric_numbers": nric_numbers,
            "credit_card_numbers": credit_card_numbers,
            "email_addresses": email_addresses,
            "phone_numbers": phone_numbers,
            "ip_addresses": ip_addresses,
        }

        return json.dumps(SensitiveData, indent=4)


    def replace_sensitive_data(self):
        """

        Replaces sensitive data in a given piece of text using regular expressions.

        """

        self.dictOfSensitiveData = self.nric_regex.sub("[nric_protected]", self.dictOfSensitiveData)
        self.dictOfSensitiveData = self.credit_card_regex.sub("[XXXX-XXXX-XXXX-XXXX]", self.dictOfSensitiveData)
        self.dictOfSensitiveData = self.email_regex.sub("[support@tomtomload.com] ", self.dictOfSensitiveData)
        self.dictOfSensitiveData = self.phone_regex.sub("[phone_protected]", self.dictOfSensitiveData)
        self.dictOfSensitiveData = self.ip_regex.sub("[ip_protected]", self.dictOfSensitiveData)

        self.dictOfSensitiveData = json.loads(self.dictOfSensitiveData)

        return str(self.dictOfSensitiveData)



# if __name__ == '__main__':

    # dictOfSensitiveData = {
    #     "nric_numbers": "S1234567B",
    #     "credit_card_numbers": "1234-1234-1234-1234",
    #     "email_addresses": "l@gmaol.com",
    #     "phone_numbers": "+6512345678",
    #     "ip_addresses": "90.65.1.1",
    # }

#     sensitive_data = DataLossPrevention(dictOfSensitiveData)

#     sensitive_data.detect_sensitive_data()
#     print(sensitive_data.replace_sensitive_data().encode('utf-8'))
