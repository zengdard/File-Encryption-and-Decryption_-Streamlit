import streamlit as st
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import os
import hashlib
import io
import pickle
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
    cipher = ChaCha20.new(key=key)
    data = file.getvalue()
    ciphertext = cipher.encrypt(data)

    file_info = {
        'nonce': cipher.nonce,
        'ciphertext': ciphertext,
        'extension': os.path.splitext(file.name)[1]
    }

    return pickle.dumps(file_info)

def decrypt_file(file_info, key):
    file_info_dict = pickle.loads(file_info)
    nonce = file_info_dict['nonce']
    ciphertext = file_info_dict['ciphertext']

    cipher = ChaCha20.new(key=key, nonce=nonce)
    data = cipher.decrypt(ciphertext)

    return data, file_info_dict['extension']

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

    if key_input:
        key = get_key(key_input)
    else:
        if st.button("Générer une clé"):
            key = get_random_bytes(32)
            key_str = b64encode(key).decode()
            st.success(f"Clé générée (Gardez-la précieusement, nous ne la sauvegarderons pas !): {key_str}")

    uploaded_file = st.file_uploader("Choisissez un fichier à chiffrer", type=["png", "jpg", "txt", "pdf", "enc"])

    if st.button("Chiffrer"):
        if uploaded_file and key:
            file_bytes = uploaded_file.read()
            file_to_encrypt = io.BytesIO(file_bytes)

            encrypted_file_info = encrypt_file(file_to_encrypt, key)
            st.success("Fichier chiffré !")

            # Offer the encrypted file info for download
            st.download_button(
                label="Télécharger le fichier chiffré",
                data=encrypted_file_info,
                file_name='encrypted_file.enc',
                mime='application/octet-stream'
            )

    if st.button("Déchiffrer"):
        if uploaded_file and key:
            #try:
                decrypted_data, file_extension = decrypt_file(uploaded_file.read(), key)
                decrypted_file = io.BytesIO(decrypted_data)
                st.download_button(
                    label="Télécharger le fichier déchiffré",
                    data=decrypted_file,
                    file_name=f'decrypted_file{file_extension}',
                    mime='application/octet-stream'
                )
