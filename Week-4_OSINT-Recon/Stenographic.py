from PIL import Image

def to_bin(data):
    """Convert data to binary format as string"""
    if isinstance(data, str):
        return ''.join(format(ord(i), '08b') for i in data)
    elif isinstance(data, bytes) or isinstance(data, bytearray):
        return ''.join(format(i, '08b') for i in data)
    elif isinstance(data, int):
        return format(data, '08b')
    else:
        raise TypeError("Type not supported.")

def encode(image_path, message, output_path):
    """Encode a message into an image"""
    img = Image.open(image_path)
    if img.mode != 'RGB':
        raise ValueError("Image mode needs to be RGB")

    encoded = img.copy()
    width, height = img.size
    bin_message = to_bin(message) + '1111111111111110'  # Delimiter

    data_index = 0
    for y in range(height):
        for x in range(width):
            pixel = list(img.getpixel((x, y)))
            for n in range(3):  # R, G, B
                if data_index < len(bin_message):
                    pixel[n] = pixel[n] & ~1 | int(bin_message[data_index])
                    data_index += 1
            encoded.putpixel((x, y), tuple(pixel))
            if data_index >= len(bin_message):
                encoded.save(output_path)
                print(f"[+] Message successfully encoded into {output_path}")
                return
    raise ValueError("Message too long to encode in image.")

def decode(image_path):
    """Decode a hidden message from an image"""
    img = Image.open(image_path)
    bin_data = ''
    for y in range(img.size[1]):
        for x in range(img.size[0]):
            pixel = img.getpixel((x, y))
            for n in range(3):  # R, G, B
                bin_data += str(pixel[n] & 1)

    # Split by 8-bits
    all_bytes = [bin_data[i:i+8] for i in range(0, len(bin_data), 8)]
    decoded = ''
    for byte in all_bytes:
        if byte == '11111110':  # Delimiter
            break
        decoded += chr(int(byte, 2))
    return decoded


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="LSB Image Steganography")
    parser.add_argument('mode', choices=['encode', 'decode'], help='Operation mode')
    parser.add_argument('--infile', help='Input image file')
    parser.add_argument('--outfile', help='Output image file (for encoding)')
    parser.add_argument('--message', help='Message to hide (for encoding)')

    args = parser.parse_args()

    if args.mode == 'encode':
        if not args.infile or not args.outfile or not args.message:
            print("[-] Missing parameters for encoding.")
        else:
            encode(args.infile, args.message, args.outfile)

    elif args.mode == 'decode':
        if not args.infile:
            print("[-] Input image required for decoding.")
        else:
            message = decode(args.infile)
            print("[+] Hidden message extracted:")
            print(message)
