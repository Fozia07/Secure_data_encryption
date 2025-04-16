# Secure Data Encryption Program using streamlit

import streamlit as st
import hashlib
import json
import os 
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

### data information from user

Data_File ="secure_data.json"
SALT=b"secure_salt_value"
LOCKOUT_DURATION = 60

# section login detail

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user =None

if "failed_attempt" not in st.session_state:
    st.session_state.failed_attempt = 0

if "Lockout_time" not in st.session_state:
    st.session_state.Lockout_time = 0


def load_data():
    if os.path.exists(Data_File):
       with open(Data_File , "r") as f:
        return json.load(f)

    return {}   

def Save_data(data):
   with open(Data_File , "w") as f:
      json.dump(data , f)


def generate_key (passkey):
    key=pbkdf2_hmac("sha256", passkey.encode(), SALT , 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
   return hashlib.pbkdf2_hmac("sha256",password.encode(),SALT,100000).hex()


# cryptography fernet use

def encrypt_text(text , key):
   cipher = Fernet(generate_key(key))
   return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text ,key):
   try:
      cipher=Fernet(generate_key(key))
      return cipher.decrypt(encrypt_text.enecode()).decode()
   except:
    return  None
   
store_data =load_data()  


#navigation bar
st.tittle="🔐Secure Data Encryption"
menu=["Home","Register","Login","Store_data","Retrieve data"]
choice= st.sidebar.selectbox("Navigation",menu)


#home page

if choice == "Home":
   st.subheader("🔐Welcome to my secure Data Ecyrption System Using Streamlit")
   st.markdown("👩‍💻Develope a streamlit_base secure data storage")


# register

if choice == "Register":
   st.header("📝Register New user")
   username= st.text_input("Enter the user_name")
   password=st.text_input("create password", type="password")

   if st.button("Register"):
     if username in store_data:
       st.warning("❌User already exists")

     else:
       store_data[username] ={
          "password":hash_password(password),
           "data":[]
       }
       Save_data(store_data)
       st.success("✅user sucessfully register")
   else:
     st.error("❌Both feilds are require")     

elif choice == "Login":
   st.subheader("user login")

   if time.time() < st.session_state.lockout_time():
      remaining =int(st.session_state.lockout_time -time())
      st.warning(f"to many failed attempt ,please try after {remaining} second")
      st.stop()

   # Login Page
elif choice == "Login":
    st.subheader("User Login")

    # Check lockout timer
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.warning(f"⚠️ Too many failed attempts. Please try again in {remaining} seconds.")
        st.stop()

    # Input fields (placed outside the button check)
    username = st.text_input("Enter username")
    password = st.text_input("Enter password", type="password")

    # Login button
    if st.button("Login"):
        if username in store_data and store_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Remaining attempts: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("⛔ Too many failed attempts. Locked for 60 seconds.")
                st.stop()

 # store data 
elif choice == "Store_data":
   if not st.session_state.authenticated_user :
      st.warning("❌please login first")

   else:
      st.subheader("📋Store Encrypted Data")
      data= st.text_area("Enter data to encrypt")
      passkey=st.text_input("Encryption key(passpharse)",type="password")   

      if st.button("Enter encrypted data"):
         if data and passkey:
            encrypted=encrypt_text(data ,passkey)
            store_data[st.session_state.authenticated_user]["data"].append(encrypted)
            Save_data(store_data)
            st.success("✅Data encrypted and save successfully")

         else:
            st.error("❌All feilds are required to fill")

# retrieve data
elif choice == "Retrieve data":
   if not st.session_state.authenticated_user:
      st.warning("❌please login first")           

   else:
      st.subheader("🔍Retrieve Data")
      user_data=store_data.get(st.session_state.authenticated_user, {}).get("data",[])       

      if not user_data:
         st.info("no data found")
      else:
         st.write("Encryoted data enteried: ")
         for i, item in enumerate(user_data):
            st.code(item, language="text")

         encrypted_input=st.text_input("Enter encryptted text")
         passkey= st.text_input("Enter the passkey T decrpt", type="password")      

         if st.button("Decrypt"):
            result= decrypt_text(encrypted_input, passkey)
            if result:
               st.success(f"✅decrypted : {result}")
            else:
               st.error("❌incorrect passkey and curpted data")  
