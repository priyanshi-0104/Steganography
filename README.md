# Steganography Project (Text, Image, Audio & Video)

## 📌 Project Overview

This project demonstrates **Steganography**, the technique of hiding secret information inside normal media files so that the existence of the message is not easily noticeable.

In this project, a **single encode and decode logic** is implemented for:

* 📄 Text files
* 🖼 Images (PNG)
* 🔊 Audio (WAV)
* 🎥 Video (MP4)

The project uses **Least Significant Bit (LSB) steganography**, which modifies only the last bit of data, ensuring minimal perceptual change.

---

## 🧠 How Steganography Works (Simple Explanation)

* Every digital file (image, audio, video) is made of binary data (0s and 1s)
* The **LSB method** replaces the last bit of pixels / samples with secret data
* Since only the last bit changes, the human eye or ear cannot detect the difference

---

## 🛠 Technologies Used

* **Python 3**
* **Pillow (PIL)** – Image processing
* **OpenCV (cv2)** – Video processing
* **wave** – Audio file handling (built-in module)
* **NumPy** – Efficient numerical and bitwise operations

---

## 📁 Project Structure

```
Steganography/
│
├── encode.py          # Encode secret message
├── decode.py          # Decode hidden message
├── requirements.txt   # Required libraries
│
└── sample_files/
    ├── input.png      # Image input
    ├── input.wav      # Audio input
    ├── input.mp4      # Video input
    └── text.txt       # Text input
```

---

## 📦 Installation

### 1️⃣ Install Python libraries

```bash
pip install -r requirements.txt
```

### 2️⃣ Ensure sample files exist

Add your input files inside the `sample_files` folder.

---

## ▶️ How to Run

### 🔐 Encoding a Message

```bash
python encode.py
```

Choose:

* 1 → Text
* 2 → Image
* 3 → Audio
* 4 → Video

Enter the secret message and the input file when prompted.

---

### 🔓 Decoding a Message

```bash
python decode.py
```

Choose the same file type to extract the hidden message.

---

## 🔑 Stop Marker Used

* Binary stop marker: `11111111`
* Character equivalent: `\xff`

This marker tells the decoder where the secret message ends, making decoding faster and efficient.

---

## ⚠ Common Issues & Fixes

### 🔸 Audio Error (Read-only Buffer)

**Cause:** `np.frombuffer()` returns a read-only array

**Fix:**

```python
samples = np.frombuffer(frames, dtype=np.int16).copy()
```

---

### 🔸 Video Overflow Error

**Cause:** Using `~1` on uint8 values

**Fix:**

```python
frame[y][x][0] = (frame[y][x][0] & 254) | bit
```

---

### 🔸 Slow Video Decoding

**Fix:** Stop decoding as soon as stop marker is detected

---

## 🎓 Viva / Interview Explanation (Short)

> This project uses LSB steganography to hide messages inside text, images, audio, and video files. The least significant bit of data is modified, which does not affect the quality of the original file. NumPy is used for efficient bit manipulation, and decoding stops as soon as a stop marker is detected for better performance.

---

## 🚀 Future Improvements

* Encryption before embedding
* Password-protected decoding
* GUI interface
* Support for more file formats

---

## ✅ Project Status

✔ Beginner-friendly
✔ Interview-ready
✔ GitHub-ready
✔ College project approved

---

### 👩‍💻 Author

**Priyanshi Gupta**

---

⭐ If you like this project, don’t forget to star the repository!
