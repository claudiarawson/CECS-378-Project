from PIL import Image

payload_path = "./payload.py"
img_path = "./uuh.png"
out_path = "./tainted.png"

# Convert character to list of bits
def ctob(c):
    output = [0]*8 # Default 0 to replace with 1 when needed
    c_val = ord(c)

    bit_count = 7 # Big Endian
    for i in range(len(output)):
        bit_value = pow(2, bit_count)
        if bit_value <= c_val:
            c_val -= bit_value
            output[i] = 1
        bit_count -= 1    

    return output

# Pull in payload text as bits
payload = []
with open(payload_path, "r") as file:
    content = file.read()
    for c in content:
       payload.extend(ctob(c)) 



# Pull in image as RGB file
image = Image.open(img_path)
rgb_image = image.convert("RGB").load()


