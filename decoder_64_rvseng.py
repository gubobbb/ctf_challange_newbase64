import os

def char_gen():
    """
    Generates the custom 64-character alphabet used for encoding.
    This function must be identical to the one in the original script.
    """
    # Start with Thai consonants
    char = [chr(i) for i in range(ord('ก'), ord('ก') + 47)]
    # Add Thai digits
    char += [chr(i) for i in range(ord('๐'), ord('๐') + 10)]
    # Add ASCII digits
    char += [chr(i) for i in range(ord('0'), ord('0') + 10)]
    # Truncate to the first 64 characters
    char = char[:64]
    return char

def base64_decode(encoded_msg):
    """
    Decodes the custom Base64 string back to the original message.

    Args:
        encoded_msg (str): The custom Base64 string (without the '==' padding).

    Returns:
        str: The decoded original message.
    """
    # 1. Recreate the alphabet and a reverse lookup dictionary
    char = char_gen()
    char_to_index = {c: i for i, c in enumerate(char)}

    # 2. Convert the Base64 string back to a large integer
    msg_num = 0
    for c in encoded_msg:
        # Multiply by 64 (the base) and add the character's value
        msg_num = msg_num * 64 + char_to_index[c]
    
    # 3. Convert the large integer to its hexadecimal representation
    # The hex() function adds '0x' to the start, so we slice it off.
    hex_data = hex(msg_num)[2:]
    
    # Pad the hex string with a leading '0' if its length is odd
    # This ensures it can be converted to bytes correctly.
    if len(hex_data) % 2 != 0:
        hex_data = '0' + hex_data

    # 4. Convert the hexadecimal string back to bytes
    try:
        byte_data = bytes.fromhex(hex_data)
    except ValueError as e:
        print(f"Error converting hex to bytes: {e}")
        return ""
    
    # 5. Decode the bytes back into a string using UTF-8 (default encoding)
    decoded_msg = byte_data.decode('utf-8')
    
    return decoded_msg

# --- Main script execution ---
if __name__ == "__main__":
    file_path = 'enc.txt'

    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' was not found.")
    else:
        # The original script saves the file in UTF-16 encoding,
        # so we must read it with the same encoding.
        try:
            with open(file_path, 'rb') as f:
                encoded_msg_with_padding = f.read().decode('utf-16')
            
            # The original script always adds '==', which needs to be removed.
            encoded_msg = encoded_msg_with_padding.removesuffix('==')
            
            # Decode the message and print the result
            original_msg = base64_decode(encoded_msg)
            print(f"Decoded Message: {original_msg}")

        except Exception as e:
            print(f"An error occurred during file processing: {e}")
