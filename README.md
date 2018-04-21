# Twilio recording decryption in python
As per https://www.twilio.com/docs/voice/tutorials/call-recording-encryption

## Install
`pip install -r requirements.txt`

## Configure
Replace `TWILIO_SID`, `TWILIO_AUTH_TOKEN`, `PRIVATE_KEY`, `PORT`, `CHUNK_SIZE` in config.py as needed

## Run server
`python twilio_decryption.py`

## Listen to decrypted recording
Point browser to http://localhost:4200/<RECORDING_SID>
