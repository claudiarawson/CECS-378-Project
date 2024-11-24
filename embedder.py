from PIL import Image, PngImagePlugin 
import base64 
def encode_file_to_base64(file_path): 
    with open(file_path, 'rb') as file: 
        encoded_string = base64.b64encode(file.read()).decode('utf-8') 
        return encoded_string 
    
# Encode the Python file 
python_file = './payload.py' 
encoded_string = encode_file_to_base64(python_file) 

# Save the encoded string to a file (optional, for reference) 
with open('encoded_python_file.txt', 'w') as file: 
    file.write(encoded_string) 
    print("Python file encoded successfully!") 
    
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
        
def embed_data_in_image(input_image_path, output_image_path, data): 
    # Open the image 
    image = Image.open(input_image_path)
    # Create a PngInfo object to store metadata 
    metadata = PngImagePlugin.PngInfo() 
    metadata.add_text("python_file", data) 
    # Save the image with the embedded data 
    image.save(output_image_path, "PNG", pnginfo=metadata) 

# Embed the encoded Python file into the image 
input_image = 'uuh.png' 
# Image to use 
output_image = 'tainted.png' # Image with embedded data 
embed_data_in_image(input_image, output_image, encoded_string) 
print("Python file embedded successfully!")
