buf=PAYVAL 
payload = bytes(bytearray(buf))
with open('payload.bin', 'wb') as f:
    f.write(payload)
