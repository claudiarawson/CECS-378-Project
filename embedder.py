from PIL import Image

def embed_script_in_image(script_path, image_path, output_path):
    # Read the script content
    with open(script_path, "rb") as file:  # Open as binary to preserve byte structure
        content = file.read()

    len_cont = len(content) * 8  # Total length in bits
    length_bits = [int(bit) for bit in f"{len_cont:032b}"]  # 32-bit length

    # Convert script to binary (byte-by-byte)
    script_bits = []
    for byte in content:
        script_bits.extend([int(bit) for bit in f"{byte:08b}"])

    # Combine length and script bits
    payload_bits = length_bits + script_bits

    # Open the image
    image = Image.open(image_path)
    pixels = image.load()
    width, height = image.size

    # Embed the bits into the image
    bit_index = 0
    for y in range(height):
        for x in range(width):
            if bit_index < len(payload_bits):
                r, g, b = pixels[x, y]
                r = (r & ~1) | payload_bits[bit_index]  # Embed in Red LSB
                if bit_index + 1 < len(payload_bits):
                    g = (g & ~1) | payload_bits[bit_index + 1]  # Embed in Green LSB
                if bit_index + 2 < len(payload_bits):
                    b = (b & ~1) | payload_bits[bit_index + 2]  # Embed in Blue LSB
                pixels[x, y] = (r, g, b)
                bit_index += 3
            else:
                break
        if bit_index >= len(payload_bits):
            break

    # Save the output image as PNG to preserve data
    image.save(output_path, format="PNG")
    print(f"Data embedded successfully into {output_path}")

# Call the function
embed_script_in_image("payload.py", "./uuh.png", "./tainted.png")

