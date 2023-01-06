import re


class RegexChecker:
    def __init__(self):
        pass

    def no_id_checker(self, id: str, length: int = 32):

        searched_value = re.search("[0-9]{" + length + "}", id)

        try:
            if searched_value.index() == 0:
                return True

        except:
            return False

    def alphaNo_id_checker(self, id: str, length: int = 32):
        searched_value = re.search("[a-z0-9]{" + length + "}", id)

        try:
            if searched_value.index() == 0:
                return True

        except:
            return False
