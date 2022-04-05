from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):
    
    M = Secret(utils.get_random_num(bits=128))
    R1 = Secret(utils.get_random_num(bits=128))
    R2 = Secret(utils.get_random_num(bits=128))

    # Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    C1, C2=CreateCipher(R1, M, G, H)
    D1, D2=CreateCipher(R2, M, G, H)

    # Generate a NIZK proving equality of the plaintexts
    stmt = DLRep(C1, R1*G) & DLRep(C2, R1*H+M *
               G) & DLRep(D1, R2*G) & DLRep(D2, R2*H+M*G)
    zk_proof = stmt.prove()
    
    # Return two ciphertexts and the proof
    return (C1, C2), (D1, D2), zk_proof


#A function for create ciphertext
def CreateCipher(r, m, G, H):
    a = r.value * G
    b = r.value * H + m.value * G
    return a, b
