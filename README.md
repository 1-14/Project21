# Project21

## 什么是Schnorr签名

Schnorr 签名的生成使用了一个点 R 和一个标量s来代替ECDSA中的两个标量（r，s）。与 ECDSA 相似的是，R 是椭圆曲线（R=K×G）上的一个随机点。

签名的第二部分计算略有不同: s = k + hash(P,R,m) ⋅ pk。这里的 pk 是你的私钥，而P = pk×G 则是你的公钥，m 是消息。然后可通过检查 s×G = R + hash(P,R,m)×P 来验证这个签名。

下面是Schnorr签名算法的可视图

![image](https://github.com/1-14/Project21/blob/main/%E6%88%AA%E5%9B%BE/2.jpg)

这个方程是线性的，所以方程可互相加减，并且仍然有效，这就给我们带来了几大关于 Schnorr 签名的好处。

## Schnorr签名的批量验证

在比特币中，要验证比特币区块链中的区块，我们需确保区块中的所有签名都有效。如果其中一个是无效的，我们不会在乎是哪个无效的，我们只会拒绝掉整个区块。

对于 ECDSA 签名算法，每个签名都必须单独验证。也就是说，如果区块中有 1000 个签名，我们就需要计算 1000 次倒置和 2000 次点乘运算，总共约 3000 次繁重的计算任务。

而通过使用 Schnorr 签名，我们可以将所有签名验证方程相加，从而节省一些计算能力。对于有 1000 个签名的区块而言，我们需验证：

(s1+s2+…+s1000)×G=(R1+…+R1000)+(hash(P1,R1,m1)×P1+ hash(P2,R2,m2)×P2+…+hash(P1000,R1000,m1000)×P1000)

这里我们有一堆加法（在计算能力上几乎是免费的）以及 1001 次点乘法。我们需要为每个签名计算大约一次繁重的计算。

下面是两个签名的批验证图，由于验证方程是线性的，只要所有签名都有效，几个方程的和就有效。我们节省了一些计算能力，因为标量和点加法比点乘法容易得多

![image](https://github.com/1-14/Project21/blob/main/%E6%88%AA%E5%9B%BE/3.jpg)

## 签名流程

![image](https://github.com/1-14/Project21/blob/main/%E6%88%AA%E5%9B%BE/4.png)

## 批量验签流程

![image](https://github.com/1-14/Project21/blob/main/%E6%88%AA%E5%9B%BE/5.png)

## 关键代码展示

#### Schnorr签名和验证

```
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
```

#### 批量验签

```
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
```

## 运行结果展示

![image](https://github.com/1-14/Project21/blob/main/%E6%88%AA%E5%9B%BE/1.png)

## 参考资料

https://blog.csdn.net/ComingChat/article/details/120154502

https://www.btcstudy.org/2021/12/06/schnorr-applications-batch-verification/

https://blog.csdn.net/qq_41546054/article/details/122283955




