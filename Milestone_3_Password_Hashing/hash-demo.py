# Python 3 standard library; dummy values only.
import hashlib, secrets, hmac
password=b"dummy-practice-value"
salt1=secrets.token_bytes(16); salt2=secrets.token_bytes(16)
def derive(value,salt): return hashlib.pbkdf2_hmac("sha256",value,salt,100000)
a=derive(password,salt1);b=derive(password,salt2)
print("Different salts:",salt1!=salt2)
print("Different hashes:",a!=b)
print("Correct value:",hmac.compare_digest(a,derive(password,salt1)))
print("Wrong value:",hmac.compare_digest(a,derive(b"wrong-dummy",salt1)))
# Educational experiment, not a complete production authentication implementation.
