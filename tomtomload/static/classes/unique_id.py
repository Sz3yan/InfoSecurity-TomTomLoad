import uuid
from typing import Optional


class UniqueID:
    # -----------------  USAGE OF UniqueID  ----------------- #

    # Generates a unique ID (16 bytes)
    #     | -- default is 1
    #     | -- if you want more than 1, pass the number of times you want to generate a 16 byte ID

    # -----------------  END USAGE OF UniqueID ----------------- #

    def __init__(self, NumOfSixteenBytes:Optional[int]=1):
        self.NumOfSixteenBytes = NumOfSixteenBytes

    def generate_id(self) -> str:
        if (self.NumOfSixteenBytes == 1):
            return uuid.uuid4().hex

        elif (self.NumOfSixteenBytes > 1):
            return "".join([uuid.uuid4().hex for _ in range(self.NumOfSixteenBytes)])

        else:
            raise ValueError("The number of times to generate a 16 byte ID must be greater than 0.")    

    def __str__(self) -> str:
        return self.generate_id()

    def __len__(self) -> int:
        return len(self.generate_id())


if __name__ == "__main__":
    a = UniqueID()

    print(a.generate_id())