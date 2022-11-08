#from fastecdsa.curve import secp256k1
#from fastecdsa.point import Point
#from fastecdsa.util import mod_sqrt

from Crypto.PublicKey import RSA
from random import randrange
from math import log2, ceil, gcd
from Crypto.Hash import keccak



#Parameters for PRNG
tilde_n = 0xa709e2f84ac0e21eb0caa018cf7f697f774e96f8115fc2359e9cf60b1dd8d4048d974cdf8422bef6be3c162b04b916f7ea2133f0e3e4e0eee164859bd9c1e0ef0357c142f4f633b4add4aab86c8f8895cd33fbf4e024d9a3ad6be6267570b4a72d2c34354e0139e74ada665a16a2611490debb8e131a6cffc7ef25e74240803dd71a4fcd953c988111b0aa9bbc4c57024fc5e8c4462ad9049c7f1abed859c63455fa6d58b5cc34a3d3206ff74b9e96c336dbacf0cdd18ed0c66796ce00ab07f36b24cbe3342523fd8215a8e77f89e86a08db911f237459388dee642dae7cb2644a03e71ed5c6fa5077cf4090fafa556048b536b879a88f628698f0c7b420c4b7;

tilde_a = 0x2834a0d0c6bb078e5ca937b209fc8f221f5a7988c62ec591520a347419440ff67c479eadb6f76833631886c7b99b027f8d587eec268bd75222a918c893f7e9f171f4866b72f1375f00a5f128f948a543c85d9d7fcd29fa6fee0193d38d136caeccf3284aaafd5872af591429c4f4d44e00e5fa9cb97a46bbd022be308a6510f5c4c5b3c89b85dad796388bd5bc898985d02ef75e0eefb4920516ebc17a9b096f5474b4d700680f2bbf363b121a63f1a4303dda32d6a0606a641dc9449a92dd82dc922a1406d4c489d25dbc37923825bcd9f6ea860ed5e1d18c9753ee378176d39f428fd9b0840ea1078c27d7e4ccbdbf8aee40371abaa787383ed1f5890a760;
tilde_b = 0x13110fc6f7a0774874ec6e7976f4915668227ba12a8a2936f686d85bb47eccd947a93dceaefff0780b47f5ea460b3cc3d3e4069f07e7be367c667fc7cebfaaea6da4b3408a2ebb325195f990f82b687e3e59642b36b7c5c4ca8a5a06fa7b8d54ff46d89825b3b0e21114efab0564aab5d4f3aafa65c7a26dc07b9d17747f10a29301d4861bd1db823b2af093a50d705ccebb0bed6f453da7ba4eee6306d9556f38b9650774b65a3695b78afa5b07ebf6ce53331e894582ea360dd5ff3cdff257d7849bd4e982edd04ab1e2e84e88b1431bbe30a6b4d0c00db37ca721aab39a3bcd379153190b2fafbf30c631c10e48b6efb54206fed38049ee7f8ea780d34b5b;

###Computes efficiently x^y mod n
def fast_power(x, y, n):

    result = 1
    while power > 0:
        # If power is even
        if power % 2 == 0:
            # Divide the power by 2
            power = power // 2
            # Multiply base to itself
            base = base * base
        else:
            # Decrement the power by 1 and make it even
            power = power - 1
            # Take care of the extra value that we took out
            # We will store it directly in result
            result = result * base

            # Now power is even, so we can follow our previous procedure
            power = power // 2
            base = base * base

    return result

#Converting noise affecting integers in Zn to interger in [-w , w]
def noise_conversion(fixed_val, fuzzy_val , public_modulus, max_noise):

    noise_term = (fuzzy_val - fixed_val)%public_modulus;
    if noise_term > max_noise:
        noise_term = -((fixed_val- fuzzy_val)%public_modulus);

    return noise_term;

#################################################################
#Fuzzy key distribution
def fuzzy_distribution(fixed_val, w, n):
    e = randrange(-w, w);
    sk = (fixed_val + e)%n;
    return sk;


#####################################################################################
#Key enrollment and fuzzy signing for user
#For the public key, we use only the x coordinate
class RSA_user:
    def __init__(self, w):

        KeyGen_values = RSA.generate(2048); #generate secure RSA parameters for a modulus with bit length 2048

        n = KeyGen_values.n; #public modulus
        phi_val = (KeyGen_values.p-1)*(KeyGen_values.q-1);

        #multiply e by random constant until a coprime with phi = (p-1)*(q-1)
        #the resulting e is the encryption exponent
        gcd_val = 0;
        while gcd_val != 1:
            coeff_e = randrange(n);
            e = (KeyGen_values.e*coeff_e)%n;
            gcd_val = gcd(e,phi_val);

        d = pow(e, -1, (KeyGen_values.p-1)*(KeyGen_values.q-1)); #compute inverse of e to obtain decryption exponent
        fuzzy_sk = fuzzy_distribution(e, w, n);
        self.fixed_sk = e;
        self.enrolled_sk = fuzzy_sk;

        noise_term = noise_conversion(e, fuzzy_sk , n, w);

        self.enrolled_noise = noise_term;
        self.public_key = [n, d];
        self.max_noise = w;


    #Fuzzy signing algorithm. NOTICE that we do not consider a secure RSA signing scheme (e.g., no padding, etc.)
    def fuzzy_signature(self, m):

        #Hashing the message into integer
        d = keccak.new(digest_bits=256)
        d.update(m.encode('utf8'))
        m = int(d.hexdigest(), 16);

        #Sampling fuzzy secret key
        sk = fuzzy_distribution(self.fixed_sk, self.max_noise, self.public_key[0]);

#        print("--> Sampled sk is "+hex(sk));
        print("--> Noise term is "+str(noise_conversion(self.fixed_sk, sk , self.public_key[0], self.max_noise)));

        #Signing
        signature = pow(m, sk, self.public_key[0]);
        return signature;


#####################################################################################
#PRNG for ECDSA
def prng(w, X, prng_input, n):

    d = keccak.new(digest_bits=512)
    d.update(prng_input.encode('utf8'))
    digest_val = int(d.hexdigest(), 16);

    digest_val_binary = format(digest_val, "08b").zfill(512);
    
    ##Converting either into number in [0 ; 2**256]

    for i in range(X):

        delta_e_all = int(digest_val_binary[0:256],2)%n;        ##REMEMBER TO CONSIDER A PROPER PRNG WITH OUTPUT IN [0 ; tilde_n]
        y = (tilde_b*pow(tilde_a, delta_e_all, n))%n;
#        print("Coordinates of tilde Q");
#        print("--------",hex(second_point.x));
#        print("--------",hex(second_point.y));

        x = hex(y);
        d = keccak.new(digest_bits=512)
        d.update(prng_input.encode('utf8'))
        digest_val = int(d.hexdigest(), 16);
        digest_val_binary = format(digest_val, "08b").zfill(512);
    

    #final conversion
    bit_sign = 2*int(digest_val_binary[0],2)-1;
    num_bits = 1+ceil(log2(w));
    absolute_value = (int(digest_val_binary[1:1+num_bits],2))%(2*w);

    delta_e = bit_sign*absolute_value;

    return delta_e;

#####################################################################################
#Clearing algorithm
def clearing(message, w, signature, X, aux, public_key):

    n = public_key[0]; #public modulus
    d = public_key[1]; #verification exponent

    #Hashing the message into integer
    digest_object = keccak.new(digest_bits=256)
    digest_object.update(message.encode('utf8'))
    c = int(digest_object.hexdigest(), 16);

    #Generate vector to test
    test_seed = hex(randrange(2**256));
    prng_input = message+str(test_seed)+aux;
    test_delta_e = prng(w,X, prng_input, n); #generate a candidate for delta_e from PRNG

    #Compute new signature
    y = pow(signature, d, n);
    correction_term = pow(pow(c,d,n), test_delta_e, n);

    hat_c = (y*correction_term)%n;

    ok = (hat_c == c);
        
    return ok, test_seed, -test_delta_e;