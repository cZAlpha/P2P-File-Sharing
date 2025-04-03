from stegano import lsb


def create_stego_image():
    """Helper function to create steganography image"""
    # Path to the image
    image_path = "Assets/testing.png"
    # Password to hide
    admin_password = "memento_mori"
    # Hide the password inside the image
    secret_image = lsb.hide(image_path, admin_password)
    # Save the image with the hidden password
    secret_image.save("Assets/secret.png")
    print("[+] Secret password hidden in image; saved as 'secret.png'")

if __name__ == "__main__":
    create_stego_image()