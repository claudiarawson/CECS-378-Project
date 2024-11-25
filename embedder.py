from PIL import Image

def read_file_as_binary(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def ctob(c):
    output = [0] * 8  # Default 0 to replace with 1 when needed
    c_val = ord(c)
    bit_count = 7  # Big Endian
    for i in range(len(output)):
        bit_value = 2 ** bit_count
        if bit_value <= c_val:
            c_val -= bit_value
            output[i] = 1
        bit_count -= 1
    return output

def byte_to_bits(byte_data):
    bits = []
    for byte in byte_data:
        bits.extend([int(bit) for bit in format(byte, '08b')])
    return bits

def write_image_with_embedded_data(image_path, output_path, file_data):
    img = Image.open(image_path)
    img_data = list(img.getdata())
    print(f"Read image data size: {len(img_data)} pixels")

    file_bits = byte_to_bits(file_data)
    print(f"Total bits to embed: {len(file_bits)}")

    if len(img_data) * 3 * 8 < len(file_bits) + 32:
        raise ValueError("The image is too small to embed the file data.")

    # Embed the length of the file data (in bits) at the beginning
    data_length = len(file_bits)
    length_bits = []
    for byte in data_length.to_bytes(4, 'big'):
        length_bits.extend(byte_to_bits([byte]))

    data_index = 0
    bits_to_embed = length_bits + file_bits

    for i in range(len(img_data)):
        if data_index >= len(bits_to_embed):
            break
        r, g, b = img_data[i]

        if data_index < len(bits_to_embed):
            r = (r & 0xFE) | bits_to_embed[data_index]
            data_index += 1
        if data_index < len(bits_to_embed):
            g = (g & 0xFE) | bits_to_embed[data_index]
            data_index += 1
        if data_index < len(bits_to_embed):
            b = (b & 0xFE) | bits_to_embed[data_index]
            data_index += 1

        img_data[i] = (r, g, b)

    new_img = Image.new(img.mode, img.size)
    new_img.putdata(img_data)
    new_img.save(output_path)
    print(f"Python file successfully embedded into the image: {output_path}")

python_file = './payload.py'
file_data = read_file_as_binary(python_file)
write_image_with_embedded_data('uuh.png', 'tainted.png', file_data)
