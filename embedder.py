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

# Embed payload into image 
payload_index = 0
width, height = image.size

# for loop: loop over the pixels
for y in range(height):
    for x in range(width):
        # Embedding bits into different channels red, green, blue by modifying LSB
        r, g, b = rgb_image[x, y] # current value of RGB pixel
        if payload_index < len(payload):
            r = (r & 0xFE) | payload[payload_index] # modifying LSB of red channel
            payload_index += 1
        if payload_index < len(payload):
            g = (g & 0xFE) | payload[payload_index] # moddifying LSB of green channel
            payload_index += 1
        if payload_index < len(payload):
            b = (b & 0XFE) | payload[payload_index] # modifying LSB of blue channel
            payload_index +=1
        
        rgb_image[x, y] = (r, g, b) # update pixel with the modified red, green, blue channels

        if payload_index >= len(payload):
            break # if there is no more bits left to embed
    if payload_index >= len(payload):
        break # if all bit have been embedded

# save to tainted image
image.save(out_path)

# print successful embed
print(f"Successfully embedded into {out_path}")