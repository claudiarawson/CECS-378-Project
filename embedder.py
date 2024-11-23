from PIL import Image

payload_path = "./payload.py"  # Path to the payload file
img_path = "./uuh.png"         # Path to the input image
out_path = "./tainted.png"     # Path to save the output image

# Convert a character to a list of bits
def ctob(c):
    output = [0] * 8  # Default to 0s
    c_val = ord(c)

    bit_count = 7  # Big Endian
    for i in range(len(output)):
        bit_value = pow(2, bit_count)
        if bit_value <= c_val:
            c_val -= bit_value
            output[i] = 1
        bit_count -= 1

    return output

# Pull in the payload text as bits
payload = []
with open(payload_path, "r", encoding="utf-8") as file:
    content = file.read()
    for c in content:
        payload.extend(ctob(c))

# Append a delimiter ("END") to the payload
delimiter = "END"
for c in delimiter:
    payload.extend(ctob(c))

# Pull in the image as an RGB file
image = Image.open(img_path)
rgb_image = image.convert("RGB").load()

# Embed payload into the image
payload_index = 0
width, height = image.size

# Number of bits needed to embed / Number of bits in the image
total_bits = len(payload)
total_pixels = width * height * 3  # RGB channels

# Ensure payload fits inside the image
if total_bits > total_pixels:
    raise ValueError("Image is too small for the payload")

# Loop over the pixels to embed the payload
for y in range(height):
    for x in range(width):
        r, g, b = rgb_image[x, y]  # Current RGB values of the pixel
        if payload_index < len(payload):
            r = (r & 0xFE) | payload[payload_index]  # Modify LSB of red channel
            payload_index += 1
        if payload_index < len(payload):
            g = (g & 0xFE) | payload[payload_index]  # Modify LSB of green channel
            payload_index += 1
        if payload_index < len(payload):
            b = (b & 0xFE) | payload[payload_index]  # Modify LSB of blue channel
            payload_index += 1

        rgb_image[x, y] = (r, g, b)  # Update pixel with modified RGB values

        if payload_index >= len(payload):
            break  # Stop embedding if the entire payload is embedded
    if payload_index >= len(payload):
        break

# Save the tainted image
image.save(out_path)

# Print success message
print(f"Successfully embedded the payload into {out_path}")
