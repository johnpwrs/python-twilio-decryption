import requests
from config import TWILIO_SID, TWILIO_AUTH_TOKEN, PORT, PRIVATE_KEY, CHUNK_SIZE
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, Response
from requests.auth import HTTPBasicAuth
from twilio.rest import Client

app = Flask(__name__)

@app.route('/<recording_sid>')
def decrypt_recording(recording_sid):
  client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
  encrypted_recording_url = "https://api.twilio.com/2010-04-01/Accounts/%s/Recordings/%s" %(TWILIO_SID, recording_sid)

  encrypted_audio = requests.get(encrypted_recording_url, stream=True)

  # Following "Per Recording Decryption Steps (Customer)"
  # https://www.twilio.com/docs/voice/tutorials/call-recording-encryption#per-recording-decryption-steps-customer

  # 1) Obtain public_key_sid, encrypted_cek, iv parameters
  # within EncryptionDetails via recordingStatusCallback or
  # by performing a GET on the recording resource
  recording = client.recordings(sid=recording_sid).fetch()
  encryption_details = recording.encryption_details
  encrypted_cek = encryption_details.get('encrypted_cek')
  iv = encryption_details.get('iv')
  public_key_sid = encryption_details.get('public_key_sid')

  # 2) Retrieve customer private key corresponding to public_key_sid and
  # use it to decrypt base 64 decoded encrypted_cek via RSAES-OAEP-SHA256-MGF1
  key = RSA.importKey(PRIVATE_KEY)
  rsa_cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
  decrypted_cek = rsa_cipher.decrypt(encrypted_cek.decode('base64'))

  # 3) Initialize a AES256-GCM SecretKey object with decrypted CEK and base 64 decoded iv
  decryptor = Cipher(
    algorithms.AES(decrypted_cek),
    modes.GCM(iv.decode('base64')),
    backend=default_backend()
  ).decryptor()

  # 4) Decrypt encrypted recording using the SecretKey
  decrypted_audio = (decryptor.update(chunk) for chunk in encrypted_audio.iter_content(CHUNK_SIZE))

  return Response(decrypted_audio, content_type=encrypted_audio.headers['content-type'])

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, port=PORT)

