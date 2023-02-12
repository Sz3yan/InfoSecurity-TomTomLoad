import numpy as np
from PIL import Image
from typing import cast, Tuple, Iterable
import os

from ..classes.config import SECRET_CONSTANTS, Constants
output = Constants.TTL_MALWARELOGS_FOLDER
outputfile = os.path.join(output, 'steganography.txt')

#steganography with hidden text
def Decode(src):

    img = Image.open(src, 'r')
    array = np.array(list(img.getdata()))

    if img.mode == 'RGB':
        n = 3
    elif img.mode == 'RGBA':
        n = 4
    total_pixels = array.size//n

    hidden_bits = ""
    for p in range(total_pixels):
        for q in range(0, 3):
            hidden_bits += (bin(array[p][q])[2:][-1])

    hidden_bits = [hidden_bits[i:i+8] for i in range(0, len(hidden_bits), 8)]

    message = ""
    for i in range(len(hidden_bits)):
        if message[-5:] == "$t3g0":
            break
        else:
            message += chr(int(hidden_bits[i], 2))
    if "$t3g0" in message:
        hiddenmsg = message[:-5]
        file = open(outputfile,'a')
        file.write("Hidden Message:" + str(hiddenmsg))
        file.write('\n')
        file.close()
        stegfound = 0
        return stegfound
    else:
        print("No Hidden Message Found")
        stegfound = 1
        return stegfound



# #steganography using LSB
# def show_lsb(image_path, n = 2) -> None:
#     """n = least significant bits of image (i think)"""
#     image = Image.open(image_path)
#
#     # Used to set everything but the least significant n bits to 0 when
#     # using bitwise AND on an integer
#     mask = (1 << n) - 1
#
#     image_data = cast(Iterable[Tuple[int, int, int]], image.getdata())
#     color_data = [
#         (255 * ((rgb[0] & mask) + (rgb[1] & mask) + (rgb[2] & mask)) // (3 * mask),) * 3
#         for rgb in image_data
#     ]
#
#     image.putdata(color_data)  # type: ignore
#     file_name, file_extension = os.path.splitext(image_path)
#     decoded_image = image.save(file_name + "_{}LSBs".format(n) + file_extension)
#     return decoded_image
#
#
#
# show_lsb('C:\\lalala\ISPJ\\InfoSecurity-TomTomLoad\\tomtomload\\static\\images\\tomtomload.png')
