# pwhash.py

This script implements an interface to the crypt_r() routine on Linux, which is a
one-way hash function for password encryption.
## Getting Started

The crypt_r() function supports different encryption algorithms like DES, MD5, SHA-256,
SHA-512 and bcrypt.

## Examples

DES algorithm:
```python
python3 pwhash.py --text foobar --md5 --des --sha-256 --sha-512 --bcrypt 
LQisNe37dPFto
```

MD5 algorithm:
```python
python3 pwhash.py --text foobar --md5
$1$ef15ky/2$/FZ2ig8UKa2tv.Wc9.vQI/
```

SHA-265 algorithm:
```python
python3 pwhash.py --text foobar --sha-256
$5$dKfkUia2$QJdCJ/cNl8Dz16diDZt5VSsNK5FSn1v.WJO7EjqpML6
```
SHA-512 algorithm:
```python
python3 pwhash.py --text foobar --sha-512
$6$Bl6MbzZKjnlpWSfr$lpvDYzW/.0prLvaabSNebe3zNLbHn/fqQ9nzEr4N86ikgboMtSKrinCEUbec4.lqhBLnHD2yHfpOjpOYCou73/
```

bcrypt algorithm:
```python
python3 pwhash.py --text foobar --bcrypt 
$2b$12$3R8.82amXVZUc/M9v/010eFU6sOTv6S2xF3oOyqdSGF6UED5zAxsK
```
all algorithm:
```python
python3 pwhash.py --text foobar --md5 --des --sha-256 --sha-512 --bcrypt
mVavLWei38luQ
$1$6z8z04fg$hXsRJTI0U1517NKg38G9h/
$5$9U8mEp3H$lq.N5QDSJsihmmLwBCNKxImvEJ0GtsRd.o5kNc1d6D5
$6$yHm5KhRuSES1.F2W$SIxc15SZAbTB.OngDP.ICrqD/ErNn4RjljJhrjf8wF/QZf42oRE5ksu9C6Z0.C1tjykJAcYYWSKw9DhpLq9Kd0
$2b$12$kbEQgSrjAhIZcSVAlYYPKuFFJ4fYCd5lIq3hOqXsE0TCk3yIxeegS
```

## Salt string
The salt string adds randomness and uniqueness to each hashed password.
The prefix in the salt string indicates the hashing method, such as the type of the 
hash algorithm (e.g., MD5, SHA-256, etc.). Different prefixes represent different 
algorithms. For example:

* "$1$": Indicates MD5 hashing.
* "$2a$" or "$2y$": Indicates bcrypt hashing.
* "$5$": Indicates SHA-256 hashing.
* "$6$": Indicates SHA-512 hashing.

Usually the script creates each time a salt string automatically. Optional an own salt string
can be used:

```python
python3.9 pwhash.py --text foobar --bcrypt --salt '$2b$12$abcdefghijklmnopqrestu'
$2b$12$abcdefghijklmnopqrestuw0t9EKuqxbp4NhucEvg8rBw6WIn.FLi
```
