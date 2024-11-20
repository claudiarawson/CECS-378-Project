# CECS-378-Project
   Our goal is to hide ransomware (or any malware) in an image file to slip 
past anti-virus software undetected.

## embedder.py
   This is a python script used as a tool for the attacker to embed
the payload into a png file.

## payload.py
   The payload to be embedded, in our case a ransomware script.

## catalyst.py
   This is the script that will be turned into an exe to be shipped along with
the tainted png file. It reads in the data embedded in the image and runs it.

# How It's Used
   The attacker will create a payload.py file which is the malicious code.
Then, he will use the embedder.py script to embed the payload into a png file.
He will then use PyInstaller to turn catalyst.py into an exe and ship it along
with the tainted image file. Once the catalyst is run, it will pull the
embedded data and run it.
