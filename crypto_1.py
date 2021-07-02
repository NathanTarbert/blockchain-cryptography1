from flask import Flask, request
import scrypt
import hashlib,binascii,os
import hmac
import json

app =Flask(__name__)

@app.route('/crypto1/sha256', methods=["POST"])
def sha256_endpoint():
    values = request.get_json()
    if not values:
        return "Missing values", 400

    required = ["msg"]

    # text = 'exercise-cryptography'
    text = values["msg"]

    if not all(k in values for k in required):
        return "Missing values", 400
	
    data = text.encode("utf8")
    
    sha256hash = hashlib.sha256(data).digest()
    print("hash", binascii.hexlify(sha256hash))
    
    result = binascii.hexlify(sha256hash)
    response = {"hash": result.decode('ascii')}

    return json.dumps(response), 201

@app.route('/crypto1/sha512', methods=["POST"])
def sha512_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg"]
    # text = 'exercise-cryptography'
    text = values["msg"]

    if not all(k in values for k in required):
        return "Missing values", 400
	
    data = text.encode("utf8")
    
    sha512hash = hashlib.sha512(data).digest()
    print("hash", binascii.hexlify(sha512hash))
    
    result = binascii.hexlify(sha512hash)
    response = {"hash": result.decode('ascii')}

    return json.dumps(response), 201

@app.route('/crypto1/ripemd160', methods=["POST"])
def ripemd160_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg"]
    # text = 'exercise-cryptography'
    text = values["msg"]
    
    if not all(k in values for k in required):
        return "Missing values", 400
	
    data = text.encode("utf8")
    
    ripemd160 = hashlib.new('ripemd160', data).digest()
    print("RIPEMD-160:", binascii.hexlify(ripemd160))
    
    result = binascii.hexlify(ripemd160)
    response = {"hash": result.decode('ascii')}

    return json.dumps(response), 201

@app.route('/crypto1/hmac', methods=["POST"])
def hmac_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg", "key"]
    if not all(k in values for k in required):
        return "Missing values", 400

    def hmac_sha256(key, msg):
        return hmac.new(key, msg, hashlib.sha256).digest()
    # key = b"secret" to:
    keyval = values["key"]
    key = keyval.encode("utf8")
    # msg = b"exercise-cryptography"
    msgval = values["msg"]
    msg = msgval.encode("utf8")
    msg = b"exercise-cryptography"

    print(binascii.hexlify(hmac_sha256(key, msg)))

    result = binascii.hexlify(hmac_sha256(key, msg))

    response = {"hmac": result.decode('ascii')}

    return json.dumps(response), 201

@app.route('/crypto1/scrypt', methods=["POST"])
def scrypt_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400
    required = ["password", "salt"]
    if not all(k in values for k in required):
        return "Missing values", 400
    # TODO: Not Implemented Yet
    # salt = b'mysalt'
    saltval = values["salt"]
    salt = saltval.encode("utf8")
    # passwd = b'secret'
    passwdval = values["salt"]
    passwd = passwdval.encode("utf8")
    key = scrypt.hash(passwd, salt, 16384, 16, 1, 64)
    result = key.hex()
    response = {"key": result}
    return json.dumps(response), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

