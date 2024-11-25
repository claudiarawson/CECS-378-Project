from PIL import Image

def btoc(binary_data):
    byte_data = bytearray()
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        byte_data.append(int(''.join(str(b) for b in byte), 2))
    return bytes(byte_data)

def extract_file_from_image(image_path, output_file_path):
    img = Image.open(image_path)
    img_data = list(img.getdata())
    print(f"Read image data size: {len(img_data)} pixels")

    extracted_bits = []

    for i, pixel in enumerate(img_data):
        r, g, b = pixel
        extracted_bits.append(r & 1)
        extracted_bits.append(g & 1)
        extracted_bits.append(b & 1)

    # Extract the length of the file data (in bits) from the first 32 bits
    length_bits = extracted_bits[:32]
    length_bytes = btoc(length_bits)
    data_length = int.from_bytes(length_bytes, 'big')
    print(f"Data length to extract: {data_length} bits")

    extracted_data = extracted_bits[32:32 + data_length]

    file_data = btoc(extracted_data)
    with open(output_file_path, 'wb') as out_file:
        out_file.write(file_data)
        print(f"File successfully extracted and saved as {output_file_path}")

extract_file_from_image('tainted.png', 'extracted_payload.py')
