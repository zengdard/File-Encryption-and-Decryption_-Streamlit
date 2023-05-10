import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import os
import hashlib
import io
import json
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    message_info = [cipher.nonce, tag, ciphertext]
    return message_info

def decrypt_message(message_info, key):
    nonce, tag, ciphertext = message_info
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data.decode()

def get_key(key_str):
    return hashlib.sha256(key_str.encode()).digest()

def encrypt_file(file, key):
    cipher = AES.new(key, AES.MODE_EAX)
    data = file.getvalue()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    file_info = {
        'nonce': b64encode(cipher.nonce).decode(),
        'tag': b64encode(tag).decode(),
        'ciphertext': b64encode(ciphertext).decode(),
        'extension': os.path.splitext(file.name)[1]
    }

    return file_info

def decrypt_file(file_info, key):
    nonce = b64decode(file_info['nonce'])
    tag = b64decode(file_info['tag'])
    ciphertext = b64decode(file_info['ciphertext'])

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    return data, file_info['extension']


st.title("Moulin - Chiffrement et déchiffrement de textes et fichiers")

page = st.sidebar.selectbox("Choisissez une tâche", ["Chiffrement de texte", "Chiffrement de fichiers"])

if page == "Chiffrement de texte":
    st.header("Chiffrement et déchiffrement de texte ")
    key = st.text_input("Entrer votre clé", value="")
    if key:
        key = hashlib.sha256(key.encode()).digest()
    else :
        if st.button("Générer une clé"):
            key = get_random_bytes(32)
            st.success(f"Clé générée (Gardée la précieusement nous ne la sauvegarderons pas ! ): {b64encode(key).decode()}")

    message = st.text_input("Entrer le texte à dé/chiffrer")

    if st.button("Chiffrer"):
        if message and key:
            message_info = encrypt_message(message, key)
            st.text(f"Message chiffré: ")
            st.text(f"{message_info}")

    if st.button("Déchiffrer"):
        if message and key:
            try:
                decrypted_message = decrypt_message(eval(message), key)
                st.text(f"Message déchiffré : {decrypted_message}")
            except:
                st.error("Une erreur est survenue lors du déchiffrement. Vérifiez la clé et les informations du message.")
else:
    st.header("Chiffrement et déchiffrement de fichiers")
    key_input = st.text_input("Entrer votre clé de chiffrement")
    key_ = get_key(key_input)


    if key_:
        key_ = hashlib.sha256(key_.encode()).digest()
    else :
        if st.button("Générer une clé"):
            key1 = get_random_bytes(32)
            key2 = hashlib.sha256(key_.encode()).digest()
            st.success(f"Clé générée (Gardée la précieusement nous ne la sauvegarderons pas ! ): {b64encode(key1).decode()}")

    uploaded_file = st.file_uploader("Choisissez un fichier à chiffrer", type=["png", "jpg", "txt", "pdf", "enc"])

    if st.button("Chiffrer"):
        if uploaded_file and key_:
            file_bytes = uploaded_file.read()
            file_to_encrypt = io.BytesIO(file_bytes)

            encrypted_file_info = encrypt_file(file_to_encrypt, key)
            st.success("Fichier chiffré !")

            # Convert encrypted file info to string and encode it to bytes
            encrypted_file_info_bytes = json.dumps(encrypted_file_info).encode()

            # Offer the encrypted file info for download
            st.download_button(
                label="Télécharger le fichier chiffré",
                data=encrypted_file_info_bytes,
                file_name='encrypted_file.enc',
                mime='text/plain'
            )

    if st.button("Déchiffrer"):
        
        st.write(key_)
    
        try:
            decrypted_data, file_extension = decrypt_file(encrypted_file_info, key)
            decrypted_file = io.BytesIO(decrypted_data)
            st.download_button(
                label="Télécharger le fichier déchiffré",
                data=decrypted_file,
                file_name=f'decrypted_file{file_extension}',
                mime='application/octet-stream'
            )
        except:
            st.error("Une erreur est survenue lors du déchiffrement. Vérifiez la clé et les informations du fichier.")
