from random import randrange
from datetime import datetime
from Crypto.Hash import keccak
from math import log2, ceil

#Prepare raw transactions. The script simulates a certain number of users (selected at random) that prepares messages, then sign the messages with fuzzy signatures
def create_raw_transactions(max_num_tx, enrolled_users):

    num_tx = randrange(1,max_num_tx+1);

    raw_transactions = [];
    for i in range(num_tx):

        #Select random user
        id_user = randrange(len(enrolled_users));
        user = enrolled_users[id_user];

#        print("-Attempt #"+str(i));

        #Create a transaction: read timestamp; choose one of the following options. Notice that random timestamp is necessary to make the results reproducible (regardless of actual usage time)
        #Switch to next line if you want to use the current datetime
#        dt = datetime.now(); #actual date and time
        dt = randrange(2**100); #random timestamp

        m = str(dt);
    
        #m is the message that gets signed
        signature = user.fuzzy_signature(m);
        raw_transactions.append([id_user, m,signature]); #differently from ECDSA, here also the user identity is included in the raw transaction

    return raw_transactions;

#################################################################################################################################

#Create block
def create_block(aux, w, difficulty_coefficient, max_num_tx, block_number, raw_transactions, seed_values):

    difficulty, nonce = classical_pow(max_num_tx, w, difficulty_coefficient, aux, block_number, raw_transactions, seed_values);

    numTx = len(raw_transactions);
    #Create header
    header = {'parentHash':aux, 'blockNumber':block_number, 'NumTx':numTx, 'difficulty': difficulty, 'nonce':nonce}; 
    
    #Add transactions
    transactions = [];
    for i in range(len(raw_transactions)):
        
        user_id = raw_transactions[i][0];
        m = raw_transactions[i][1];
        signature = raw_transactions[i][2];
        mined_tx = {'Tx#':i, 'identity':user_id, 'timestamp':m, 'signature':hex(signature), 'PoW':seed_values[i]};
        transactions.append(mined_tx); 

    json_block = [header, transactions];

    #Compute hash of created block
    d = keccak.new(digest_bits=256);
    d.update(str(json_block).encode('utf8'))
    aux = "0x"+d.hexdigest();
	
    json_block = [header, transactions, {'hash': aux}];
        
    return aux, json_block;

#################################################################################################################################

##classical PoW: simulates the classical PoW in which one has to find a digest with a given number of zeros
def classical_pow(max_num_tx, w, difficulty_coefficient, aux, block_number, raw_transactions, seed_values):


    numTx = len(raw_transactions);
    #Create header
    block_number += 1;
    header = {'parentHash':aux, 'blockNumber':block_number, 'NumTx':numTx, 'nonce':''}; 
    
    #Add transactions
    transactions = [];
    for i in range(len(raw_transactions)):

        user_id = raw_transactions[i][0];
        m = raw_transactions[i][1];
        signature = raw_transactions[i][2];
        mined_tx = {'Tx#':i, 'identity':user_id, 'timestamp':m, 'signature':hex(signature), 'PoW':seed_values[i]};
        transactions.append(mined_tx); 

    json_block = [header, transactions];


    delta_num_tx = max_num_tx - numTx;
    if delta_num_tx == 0:
        nonce = '';
        difficulty = 0;

    else:

        #Start nonce search: test random nonce, and do hash until ell zeros are found
        ell = difficulty_coefficient+ceil(log2((4*w+1)*delta_num_tx));
        difficulty = ell;

        d = keccak.new(digest_bits=256);
        d.update(str(json_block).encode('utf8'))
        aux = d.hexdigest();

        flag_PoW = 0;
        while flag_PoW == 0:
            
            nonce = randrange(2**256);
            digest_input = aux+hex(nonce);
            
            d = keccak.new(digest_bits=256)
            d.update(digest_input.encode('utf8'))
            digest_val = int(d.hexdigest(), 16);
            digest_val_binary = format(digest_val, "08b").zfill(256);

            #Number of zeros at the beginning of digest: we want such a number to be >= ell
            num_zeros = 0;
            i = 0;
            while digest_val_binary[i]=='0':
                num_zeros += 1;
                i += 1;
            
            if num_zeros >= ell:
                flag_PoW = 1;
                nonce = hex(nonce);
                print("--> Digest of block is "+d.hexdigest());

    return difficulty, nonce;
