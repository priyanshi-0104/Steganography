from PIL import Image
import wave
import numpy as np
import cv2

print("Choose file type to decode:")
print("1. Text")
print("2. Image")
print("3. Audio")
print("4. Video")

choice = input("Enter choice (1-4): ")

binary = ""

# ---------------- TEXT ----------------
if choice == '1':
    ZERO = '\u200b'
    ONE = '\u200c'

    with open("encoded.txt", "r", encoding="utf-8") as f:
        text = f.read()

    for ch in text:
        if ch == ZERO:
            binary += '0'
        elif ch == ONE:
            binary += '1'

# ---------------- IMAGE ----------------
elif choice == '2':
    img = Image.open("encoded.png")
    pixels = img.load()

    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            binary += str(r & 1)

# ---------------- AUDIO ----------------
elif choice == '3':
    audio = wave.open("encoded.wav", "rb")
    frames = audio.readframes(audio.getnframes())
    audio.close()

    samples = np.frombuffer(frames, dtype=np.int16)

    for sample in samples:
        binary += str(sample & 1)

# ---------------- VIDEO ----------------
elif choice == '4':
    cap = cv2.VideoCapture("encoded.mp4")

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        for y in range(frame.shape[0]):
            for x in range(frame.shape[1]):
                binary += str(frame[y][x][0] & 1)

    cap.release()

else:
    print("Invalid choice")

# Convert binary to message
message = ""
for i in range(0, len(binary), 8):
    byte = binary[i:i+8]
    if byte == '11111111':
        break
    message += chr(int(byte, 2))

print("Hidden message:", message)
