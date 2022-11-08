from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from fastecdsa.util import mod_sqrt
from random import randrange
from math import log2, ceil
from Crypto.Hash import keccak


#Curve parameters
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8;
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
G = Point(Gx, Gy, curve=secp256k1);

#Parameters for PRNG
a = 0x215663abc1f254b8adc0da7a16febaa011af923d79fdef7c42930b33a81ad477;
b = 0xadf20806e521460637176e84d977e9933c49d76fcfc6e62585940927468ff53d;


#################################################################
#Fuzzy key distribution
def fuzzy_distribution(fixed_val, w):
    e = randrange(-w, w);
    sk = (fixed_val + e)%n;
    return sk;


#####################################################################################
#Key enrollment and fuzzy signing for user
#For the public key, we use only the x coordinate
class ECDSA_user:
    def __init__(self, w):
        fixed_sk = randrange(2,n);
        enrolled_sk = fuzzy_distribution(fixed_sk, w);
        noise_term = enrolled_sk - fixed_sk;
        pk = enrolled_sk*G;
        self.max_noise = w;
        self.fixed_sk = fixed_sk;
        self.public_key = pk.x;
        self.enrolled_sk = enrolled_sk;
        self.enrolled_noise = noise_term;


    #Fuzzy signing algorithm
    def fuzzy_signature(self, m):

        #Hashing the message into integer
        d = keccak.new(digest_bits=256)
        d.update(m.encode('utf8'))
        z = int(d.hexdigest(), 16);

        #Sampling fuzzy secret key
        sk = fuzzy_distribution(self.fixed_sk, self.max_noise);

        print("--> Sampled sk is "+hex(sk));
        print("--> Noise term is "+str(sk-self.fixed_sk));

        #Signing
        k = randrange(n);
        r_point = k*G;
        r = (r_point.x)%n;
        r_y = r_point.y;
        k_inv = pow(k,n-2,n);
        s = (k_inv*(z+r*sk))%n;

        v = (r_point.y)%2;
        signature = [r,s,v];
        return signature;

#####################################################################################
#Function to obtain the public key that would verify the input signature
def compute_pk(m,signature):

    #Classic ECDSA parameters
    r = signature[0];
    s = signature[1];
    v = signature[2];

    #Hashing the message into integer
    d = keccak.new(digest_bits=256)
    d.update(m.encode('utf8'))
    z = int(d.hexdigest(), 16);

    r_cube = pow(r,3,q);
    y_of_r = mod_sqrt(r_cube+7, q);

    #Use v for parity of public key
    if y_of_r[0]%2 == v:
        y_of_r = y_of_r[0];
    else:
        y_of_r = y_of_r[1];

    k_mul_G = Point(r, y_of_r, curve=secp256k1);
    r_inv = pow(r,n-2,n);
    s_mul_k_G = s*k_mul_G;

    verifying_pk = r_inv*(s_mul_k_G - z*G);



    return verifying_pk;

#####################################################################################
#PRNG for ECDSA
def prng(w, X, prng_input):

    d = keccak.new(digest_bits=512)
    d.update(prng_input.encode('utf8'))
    digest_val = int(d.hexdigest(), 16);

    digest_val_binary = format(digest_val, "08b").zfill(512);
    
    ##Converting either into number in [0 ; 2**256]

    for i in range(X):

        delta_e_all = int(digest_val_binary[0:256],2)%n;        
        first_point = delta_e_all*G;
        second_point = a*G;
#        print("Coordinates of tilde Q");
#        print("--------",hex(second_point.x));
#        print("--------",hex(second_point.y));
        final_point = first_point+second_point;

        x = hex(final_point.x);
        d = keccak.new(digest_bits=512)
        d.update(prng_input.encode('utf8'))
        digest_val = int(d.hexdigest(), 16);
        digest_val_binary = format(digest_val, "08b").zfill(512);
    

    #final conversion
    bit_sign = 2*int(digest_val_binary[0],2)-1;
    num_bits = 1+ceil(log2(w));
    absolute_value = (int(digest_val_binary[1:1+num_bits],2))%(2*w);

    delta_e = (bit_sign*absolute_value)%n;

    return delta_e;

#####################################################################################
#Clearing algorithm
def clearing(m,w,X,aux,verifying_pk,public_keys_file):

    #Generate vector to test
    test_seed = hex(randrange(2**256));
    prng_input = m+str(test_seed)+aux;
    test_delta_e = prng(w,X, prng_input); #generate a candidate for delta_e from PRNG

    #Compute new public key
    test_pk = verifying_pk + test_delta_e*G;
    test_pk_x = test_pk.x;



    ok = test_pk_x in public_keys_file;
    user_id = -1;
    if ok:
        user_id = public_keys_file.index(test_pk_x);

    if test_delta_e>2*w:
        test_delta_e = test_delta_e - n; #-n because we consider modulo reduction
        
    return ok, test_seed, test_delta_e, user_id;
