import sys
import struct
import random
from math import gcd, ceil, floor
from gmssl import sm3


def int_hex(str):
    return int(str, 16)


def sm3_hash(message):
    message = message.encode('utf-8')
    msg_list = [i for i in message]
    hash_hex = sm3.sm3_hash(msg_list)

    return hash_hex


def inv(a, m):
    if gcd(a, m) != 1:
        return None

    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        d, x, y = extended_gcd(b, a % b)
        return d, y, x - (a // b) * y

    t1, x, t2 = extended_gcd(a, m)
    return x % m


def add_ECC(P, Q):
    if P == 0:
        return Q
    if Q == 0:
        return P
    x1, y1, x2, y2 = int_hex(P[0]), int_hex(P[1]), int_hex(Q[0]), int_hex(Q[1])
    q_int = int_hex(q)
    tmp1, tmp2 = y2 - y1, inv(x2 - x1 % q_int, q_int)
    l = tmp1 * tmp2 % q_int
    x = (l * l - x1 - x2) % q_int
    y = (l * (x1 - x) - y1) % q_int
    res = (hex(x)[2:], hex(y)[2:])
    return res


def double_ECC(P):
    if P == 0:
        return P
    x1, y1 = int_hex(P[0]), int_hex(P[1])
    a_int, q_int = int_hex(a), int_hex(q)
    tmp1 = 3 * x1 * x1 + a_int
    tmp2 = inv(2 * y1, q_int)
    l = (tmp1 * tmp2) % q_int
    x = (l * l - 2 * x1) % q_int
    y = (l * (x1 - x) - y1) % q_int
    Q = (hex(x)[2:], hex(y)[2:])
    return Q


def mul_ECC(P, k):
    k_bin = bin(k)[2:]
    i = len(k_bin) - 1
    Q = P
    if i > 0:
        k = k - 2**i
        while i > 0:
            Q = double_ECC(Q)
            i -= 1
        if (k > 0):
            Q = add_ECC(Q, mul_ECC(P, k))

    return Q


def check_ECC(P):
    x, y = int_hex(P[0]), int_hex(P[1])
    q_int, a_int, b_int = int_hex(q), int_hex(a), int_hex(b)
    if (y * y) % q_int == (x * x * x + a_int * x + b_int) % q_int:
        return True
    else:
        return False

# 使用Schnorr签名算法对消息M进行签名，
# 返回签名结果(R, s, e)。其中R是椭圆曲线上的点，s是签名值，e是签名的附加信息。
def Schnorr_sign(M):
    k = random.randint(1, int_hex(n) - 1)
    R = mul_ECC(G, k)
    x_R, y_R = R[0], R[1]
    e = sm3_hash(x_R + y_R + M)
    s = hex((k + int_hex(e) * int_hex(d)) % int_hex(n))[2:]

    return R, s, e

#对给定的签名(R, s, e)进行验证，验证签名是否有效。
def Schnorr_verify(R, s, e):
    sG = mul_ECC(G, int_hex(s))
    eP = mul_ECC(P, int_hex(e))
    if sG == (add_ECC(R, eP)):
        return True
    return False

# 对一组签名(R, s, e)进行批量验证，判断它们是否都有效。
def Schnorr_verify_Batch(R_list, s_list, e_list):
    s_sum, R_sum = int_hex(s_list[0]), R_list[0]
    eP_sum = mul_ECC(P, int_hex(e_list[0]))
    for i in range(1, len(s_list)):
        s_sum += int_hex(s_list[i])
        R_sum = add_ECC(R_list[i], R_sum)

        eP = mul_ECC(P, int_hex(e_list[i]))
        eP_sum = add_ECC(eP_sum, eP)

    sG = mul_ECC(G, s_sum)
    if sG == (add_ECC(R_sum, eP_sum)):
        return True
    return False


#参数设定
q = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
a = "0"
b = "7"
x_G = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
y_G = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
G = (x_G, y_G)
n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
d = hex(random.randint(pow(2, 127), pow(2, 128)))[2:]
P = mul_ECC(G, int_hex(d))

M1 = "6666"
M2 = "7777"
M3 = "8888"

R1, s1, e1 = Schnorr_sign(M1)
print(f'R1, s1, e1: {R1, s1, e1}')

R2, s2, e2 = Schnorr_sign(M2)
print(f'R2, s2, e2: {R2, s2, e2}')

R3, s3, e3 = Schnorr_sign(M3)
print(f'R3, s3, e3: {R3, s3, e3}')

R_list = [R1, R2, R3]
s_list = [s1, s2, s3]
e_list = [e1, e2, e3]

#对三个签名的单独验证
'''
R_sum = add_ECC(R1, R2)
R_sum = add_ECC(R_sum, R3)
s_sum = hex(int_hex(s1) + int_hex(s2) + int_hex(s3))[2:]
e_sum = hex(int_hex(e1) + int_hex(e2) + int_hex(e3))[2:]

res_Batch = Schnorr_verify(R_sum, s_sum, e_sum)
print(f'Res: {res_Batch}')
print(f'R, s, e: {R_sum, s_sum, e_sum}')
'''

#对三个签名的批量验证
res_Batch = Schnorr_verify_Batch(R_list, s_list, e_list)
print(f'Res(Batch): {res_Batch}')
