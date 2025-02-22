import cv2
import os

# Load cover image
img = cv2.imread("Pikachu.jpg")  # Ensure this image exists in your working directory
if img is None:
    print("Cover image not found!")
    exit()

# Input secret message and password
msg = input("Enter secret message: ")
password = input("Enter a passcode: ")

# Save the password to a file (for demonstration purposes only)
with open("pass.txt", "w") as f:
    f.write(password)

# Embed the message into the image.
# We will write each character’s ASCII value into a pixel channel.
n = 0  # row index
m = 0  # column index
z = 0  # channel index (0=Blue, 1=Green, 2=Red in OpenCV)

for char in msg:
    # Check if we are within image boundaries
    if n >= img.shape[0] or m >= img.shape[1]:
        print("Message is too long for the image!")
        break
    # Write the ASCII value of the character into the chosen pixel channel
    img[n, m, z] = ord(char)
    n += 1
    m += 1
    z = (z + 1) % 3  # Cycle through the three channels

# Save the encrypted image as PNG to avoid lossy compression
cv2.imwrite("Encrypted_Pikachu.png", img)

# Open the image (adjust command based on your OS)
os.system("start Encrypted_Pikachu.png")  # For Windows
# For macOS use: os.system("open Encrypted_Pikachu.png")
# For Linux use: os.system("xdg-open Encrypted_Pikachu.png")

print("Secret message embedded into image!")