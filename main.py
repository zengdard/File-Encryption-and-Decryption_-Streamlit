import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import os
import hashlib

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

def encrypt_file(file, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file.read())
    file_info = [cipher.nonce, tag, ciphertext]
    return file_info

def decrypt_file(file_info, key):
    nonce, tag, ciphertext = file_info
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

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
    
    key = st.text_input("Entrer votre clé", value="")
    if key:
        key = hashlib.sha256(key.encode()).digest()
    else key:
        if st.button("Générer une clé"):
            key = get_random_bytes(32)
            st.success(f"Clé générée (Gardée la précieusement nous ne la sauvegarderons pas ! ): {b64encode(key).decode()}")

    uploaded_file = st.file_uploader("Choisissez un fichier à chiffrer", type=["png", "jpg", "txt", "pdf"])

    if st.button("Chiffrer"):
        if uploaded_file and key:
            file_info = encrypt_file(uploaded_file, key)
            st.success("Fichier chiffré !")

            # Convert encrypted file info to bytes and offer it for download
            encrypted_file = io.BytesIO(b64encode(str(file_info).encode()))
            st.download_button(
                label="Télécharger le fichier chiffré",
                data=encrypted_file,
                file_name=f'encrypted_file.enc',
                mime='text/plain'
            )


    if st.button("Déchiffrer"):
        if key:
            key = hashlib.sha256(key.encode()).digest()
            try:
                file_info = eval(file_info_text)
                decrypted_data = decrypt_file(file_info, key)

                # Get the file extension from the decrypted file info
                file_extension = file_info['extension']

                st.text(f"Fichier déchiffré : {decrypted_data}")
                decrypted_file = io.BytesIO(decrypted_data)
                st.download_button(
                    label="Télécharger le fichier déchiffré",
                    data=decrypted_file,
                    file_name=f'decrypted_file{file_extension}',
                    mime='application/octet-stream'
                )
            except:
                st.error("Une erreur est survenue lors du déchiffrement. Vérifiez la clé et les informations du fichier.")
