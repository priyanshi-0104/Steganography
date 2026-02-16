from PIL import Image
import wave
import numpy as np
import cv2

print("Choose file type to encode:")
print("1. Text")
print("2. Image")
print("3. Audio")
print("4. Video")

choice = input("Enter choice (1-4): ")
secret = input("Enter secret message: ")

# Convert secret to binary
binary = ""
for ch in secret:
    binary += format(ord(ch), '08b')
binary += '11111111'   # stop marker

# ---------------- TEXT ----------------
if choice == '1':
    ZERO = '\u200b'
    ONE = '\u200c'

    cover_text = input("Enter cover text: ")
    hidden = ""

    for bit in binary:
        hidden += ZERO if bit == '0' else ONE

    with open("encoded.txt", "w", encoding="utf-8") as f:
        f.write(cover_text + hidden)

    print("Text encoded successfully")

# ---------------- IMAGE ----------------
elif choice == '2':
    image_name = input("Enter image name: ")
    img = Image.open(image_name)
    pixels = img.load()

    index = 0
    for y in range(img.height):
        for x in range(img.width):
            if index < len(binary):
                r, g, b = pixels[x, y]
                r = (r & ~1) | int(binary[index])
                pixels[x, y] = (r, g, b)
                index += 1

    img.save("encoded.png")
    print("Image encoded successfully")

# ---------------- AUDIO ----------------
elif choice == '3':
    audio_name = input("Enter wav file name: ")
    audio = wave.open(audio_name, "rb")

    frames = audio.readframes(audio.getnframes())
    params = audio.getparams()
    audio.close()

    # 🔥 FIX HERE
    samples = np.frombuffer(frames, dtype=np.int16).copy()

    index = 0
    for i in range(len(samples)):
        if index < len(binary):
            samples[i] = (samples[i] & ~1) | int(binary[index])
            index += 1

    new_audio = wave.open("encoded.wav", "wb")
    new_audio.setparams(params)
    new_audio.writeframes(samples.tobytes())
    new_audio.close()

    print("Audio encoded successfully")


# ---------------- VIDEO ----------------
elif choice == '4':
    video_name = input("Enter video file name: ")
    cap = cv2.VideoCapture(video_name)

    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(
        "encoded.mp4",
        fourcc,
        int(cap.get(cv2.CAP_PROP_FPS)),
        (int(cap.get(3)), int(cap.get(4)))
    )

    index = 0
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        for y in range(frame.shape[0]):
            for x in range(frame.shape[1]):
                if index < len(binary):
                    # 🔥 FIXED LINE
                    frame[y][x][0] = (frame[y][x][0] & 254) | int(binary[index])
                    index += 1

        out.write(frame)

    cap.release()
    out.release()
    print("Video encoded successfully")


else:
    print("Invalid choice")
