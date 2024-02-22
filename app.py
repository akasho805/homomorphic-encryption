from flask import Flask, render_template, request
import random

# secp256k1 parameters
Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1  # The proven prime
Acurve = 0
Bcurve = 7

# Generator Point
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
GPoint = (Gx, Gy)

# Number of points in the field [Order of G]
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

h = 0o1  # Cofactor
k = random.getrandbits(256)

def modinv(a, n=Pcurve):
    """Compute the modular inverse using the Extended Euclidean Algorithm."""
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low

    if low != 1:
        raise ValueError(f"The modular inverse does not exist for {a} mod {n}")

    return lm % n


def ECadd(a, b):
    """Elliptic curve addition."""
    LamAdd = ((b[1] - a[1]) * modinv(b[0] - a[0], Pcurve)) % Pcurve
    x = (LamAdd * LamAdd - a[0] - b[0]) % Pcurve
    y = (LamAdd * (a[0] - x) - a[1]) % Pcurve
    return (x, y)

def ECdouble(a):
    """Point doubling for elliptic curves."""
    if a is None:
        return None
    Lam = ((3 * a[0] * a[0] + Acurve) * modinv((2 * a[1]), Pcurve)) % Pcurve
    x = (Lam * Lam - 2 * a[0]) % Pcurve
    y = (Lam * (a[0] - x) - a[1]) % Pcurve
    return (x, y)

def EccMultiply(GenPoint, ScalarHex):
    """Double and add multiplication for elliptic curves."""
    if ScalarHex == 0 or ScalarHex >= N:
        raise Exception("Invalid Scalar/Private Key")

    ScalarBin = str(bin(ScalarHex))[2:]
    Q = None

    for bit in ScalarBin:
        Q = ECdouble(Q)
        if bit == "1":
            if Q is None:
                Q = GenPoint
            else:
                Q = ECadd(Q, GenPoint)
    return Q

privKey = random.getrandbits(256)

def gen_pubKey(private_Key):
    """Generate the public key."""
    PublicKey = EccMultiply(GPoint, private_Key)
    return PublicKey

def encryption(Public_Key, msg):
    """Encrypt the message."""
    k = random.getrandbits(256)  # Generate a new random number for k
    C1 = EccMultiply(GPoint, k)
    C2 = EccMultiply(Public_Key, k)[0] + msg
    return (C1, C2)


def decryption(C1, C2, private_Key):
    """Decrypt the message."""
    solution = C2 - EccMultiply(C1, private_Key)[0]
    return int(solution)


def homomorphic_addition(C1_a, C2_a, C1_b, C2_b):
    """Perform homomorphic addition of two ciphertexts."""
    C1_result = ECadd(C1_a, C1_b)
    C2_result = C2_a + C2_b
    return (C1_result, C2_result)

app = Flask(__name__)

app.static_folder = 'static'

@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    # Retrieve input from the form
    message1 = int(request.form['message1'])
    message2 = int(request.form['message2'])

    # Perform computations
    (C1_a, C2_a) = encryption(gen_pubKey(privKey), message1)
    (C1_b, C2_b) = encryption(gen_pubKey(privKey), message2)
    (C1_sum, C2_sum) = homomorphic_addition(C1_a, C2_a, C1_b, C2_b)

    # Decrypt the results
    decrypted_string1 = decryption(C1_a, C2_a, privKey)
    decrypted_string2 = decryption(C1_b, C2_b, privKey)
    homomorphic_sum = decrypted_string1 + decrypted_string2

    # Render the results on the webpage, including intermediate steps
    return render_template('index.html',
                           message1=message1,
                           message2=message2,
                           C1_a=C1_a, C2_a=C2_a,
                           C1_b=C1_b, C2_b=C2_b,
                           C1_sum=C1_sum, C2_sum=C2_sum,
                           decrypted_string1=decrypted_string1,
                           decrypted_string2=decrypted_string2,
                           homomorphic_sum=homomorphic_sum)

if __name__ == '__main__':
    app.run(debug=True)

