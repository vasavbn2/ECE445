import random

class PKI:
  def __init__(self, g, q, G, pk):
    self.g = g
    self.q = q
    self.G = G
    self.pk = pk

class Prover:
    def __init__(self, public_info, private_key):
        self.public_info = public_info
        self.private_key = private_key
        self.r = None
        self.k = None

    def generate_K(self):
        self.k = (random.randint(1, 100)) % self.public_info.G
        K = ((self.public_info.g)**self.k) % self.public_info.G
        return K
    
    def generate_S(self):
        s = self.r*self.private_key + self.k
        return s

class Verifier:
    def __init__(self, public_info):
        self.public_info = public_info
        self.K = None
        self.s = None
        self.g_to_s = None
        self.r = random.randint(1, 100) % (self.public_info.G)
    
    def send_r(self):
        return self.r
    
    def verify(self, s):
        self.g_to_s = (self.public_info.g ** s) % self.public_info.G
        # print("G^s = ", self.g_to_s)
        # print("other side: ", ((self.public_info.pk**self.r)*self.K)%self.public_info.G)

        result = (self.g_to_s==((self.public_info.pk**self.r)*self.K)%self.public_info.G)
        return result
        

G = 99972531
for i in range(0, int(100)):
    success=True
    sk = random.randint(1, 100)
    g = 6
    my_pki=PKI(g, 0, G, pk=((g**sk) %G))

    lock = Verifier(my_pki)
    crypt = Prover(my_pki, sk)

    lock.K = crypt.generate_K()
    crypt.r = lock.send_r()
    success = lock.verify(crypt.generate_S())

if success:
    print("Success")  
else:
    print("Fail")  




