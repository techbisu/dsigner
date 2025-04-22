import click
import os
import PyKCS11  # For DSC Token (PKCS#11)
import fitz  # PyMuPDF for PDFs
from flask import Flask, request, jsonify, send_file
from waitress import serve
import sys
import hashlib
from threading import Lock
from endesive import pdf

app = Flask(__name__)

# Global variables for session reuse
pkcs11_lib = None
session = None
session_lock = Lock()

# Detect the PKCS#11 Library Path
def get_pkcs11_path():
    """Auto-detect the PKCS#11 token library path for various vendors."""
    possible_paths = [
        # Windows
        "C:\\Windows\\System32\\eToken.dll",
        "C:\\Windows\\System32\\wdpkcs.dll",
        "C:\\Program Files\\SafeNet\\Authentication\\SafenetAuthentication.dll",
        "C:\\Program Files\\Gemalto\\Classic Client\\pkcs11.dll",
        "C:\\Program Files\\SafeNet\\LunaSA\\pkcs11.dll",
        "C:\\Program Files\\Gemalto\\IDPrimePKCS11\\idprimepkcs11.dll",
        "C:\\Windows\\System32\\asepkcs.dll",
        "C:\\Program Files\\Athena\\ASECard Crypto\\asepkcs.dll",
        "C:\\Program Files (x86)\\HID Global\\ActivClient\\acpkcs211.dll",
        "C:\\Program Files\\HID Global\\ActivClient\\acpkcs211.dll",
        "C:\\Windows\\System32\\bit4ipki.dll",
        # Linux
        "/usr/lib/libeToken.so",
        "/usr/lib/libwdpkcs.so",
        "/usr/lib/libpkcs11.so",
        "/usr/local/lib/libpkcs11.so",
        "/usr/lib/libacpkcs211.so",
        "/usr/lib/libbit4ipki.so",
        "/usr/lib/watchdata/lib/libwdpkcs.so",
        "/usr/lib64/pkcs11/libeToken.so",
        "/usr/lib64/libwdpkcs.so",
        "/usr/lib64/libbit4ipki.so",
        # macOS
        "/usr/local/lib/libeToken.dylib",
        "/usr/local/lib/libwdpkcs.dylib",
        "/Library/Security/tokend/libpkcs11.dylib",
        "/usr/local/lib/libbit4ipki.dylib",
        "/usr/lib/pkcs11/libSoftHSM2.so",
    ]

    for path in possible_paths:
        if os.path.exists(path):
            return path

    return None

pkcs11_lib = get_pkcs11_path()

@app.route("/api/token-info", methods=["GET"])
def get_token_info():
    """Retrieve DSC token details."""
    if not pkcs11_lib:
        return jsonify({"error": "No PKCS#11 library found"}), 400

    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(pkcs11_lib)

    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        return jsonify({"error": "No DSC token detected!"}), 400

    token_info = pkcs11.getTokenInfo(slots[0])
    
    return jsonify({
        "label": token_info.label.strip(),
        "manufacturer": token_info.manufacturerID.strip(),
        "serial_number": token_info.serialNumber.strip(),
        "model": token_info.model.strip()
    })

@app.route("/api/login", methods=["POST"])
def login_token():
    """Log in to the DSC token."""
    global session
    pin = request.json.get("pin")

    if not pkcs11_lib:
        return jsonify({"error": "No PKCS#11 library found"}), 400

    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(pkcs11_lib)

    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        return jsonify({"error": "No DSC token detected!"}), 400

    with session_lock:
        if session:
            return jsonify({"message": "Already logged in!"})

        session = pkcs11.openSession(slots[0])
        try:
            session.login(pin)
            return jsonify({"message": "Login successful!"})
        except Exception as e:
            session.close()
            session = None
            return jsonify({"error": f"Login failed: {str(e)}"}), 400

@app.route('/api/logout', methods=['POST'])
def logout_token():
    """Logout from the DSC token."""
    global session

    with session_lock:
        if session is None:
            return jsonify({"message": "No active session found!"})

        try:
            session.logout()
            session.closeSession()
            session = None
            return jsonify({"message": "Logout successful!"})
        except Exception as e:
            return jsonify({"error": f"Logout failed: {str(e)}"}), 500

def sign_pdf(pdf_path, signed_pdf_path):
    """Sign a PDF using the DSC token."""
    global session

    if not session:
        raise Exception("No active DSC session. Please log in first.")

    with session_lock:
        # Get private key and certificate from the token
        private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])[0]
        certificate = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])[0]

        certificate_data = session.getAttributeValue(certificate, [PyKCS11.CKA_VALUE])[0]

        # Function to sign data using the token
        def sign(data):
            hash_digest = hashlib.sha256(data).digest()
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            signature = session.sign(private_key, hash_digest, mechanism)
            return bytes(signature)

        with open(pdf_path, "rb") as f:
            pdf_data = f.read()

        try:
            signed_pdf = pdf.cms.sign(
                pdf_data,
                certificate_data,
                sign,
                [],
                "sha256",
                contact="user@example.com",
                location="India",
                reason="Document Approval",
                signer="DSC Signer",
            )

            with open(signed_pdf_path, "wb") as f:
                f.write(signed_pdf)

            print(f"PDF successfully signed and saved to {signed_pdf_path}")
        except Exception as e:
            print(f"Error signing PDF: {str(e)}")
            raise

    return signed_pdf_path

@app.route('/api/sign-pdf', methods=['POST'])
def sign_pdf_api():
    """API Endpoint for signing PDFs."""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    pdf_file = request.files['file']

    temp_dir = "C:\\temp\\"
    os.makedirs(temp_dir, exist_ok=True)

    input_pdf = os.path.join(temp_dir, pdf_file.filename)
    output_pdf = os.path.join(temp_dir, f"signed_{pdf_file.filename}")

    pdf_file.save(input_pdf)

    try:
        signed_pdf_path = sign_pdf(input_pdf, output_pdf)
        return send_file(signed_pdf_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@click.group()
def cli():
    """DSC Signer Utility"""
    pass

@click.command()
@click.option("--host", default="0.0.0.0", help="Host to run the API")
@click.option("--port", default=5000, help="Port to run the API")
def start_api(host, port):
    """Start API service for signing PDFs"""
    serve(app, host=host, port=port)

cli.add_command(start_api)

if __name__ == "__main__":
    cli()
