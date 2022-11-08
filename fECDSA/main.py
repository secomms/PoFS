####################################################################################################
# PROGRAM TO SIMULATE THE CREATION OF BLOCKS IN A BLOCKCHAIN WITH POFS CONSENSUS
####################################################################################################

from pickle import TRUE
from random import seed, randrange
from datetime import datetime, timedelta
from Crypto.Hash import keccak
import json
from numpy import zeros

from ECDSA_utils import ECDSA_user, compute_pk, clearing
from blockchain_utils import create_raw_transactions, create_block
from simulation_utils import print_users, print_NetworkInfo
from timeit import default_timer as timer



###### NETWORK PARAMETERS
N = 5; #number of users to be identified/authenticated
w = 2**8; #noise parameter
X = 3; #setting for PRNG
max_num_tx = 3; #max number of transactions in each block
difficulty_coefficient = 4; #parameter for classical PoW phase


###### SETTING FOR SIMULATION
seed_value = 0; #seed to use for the simulation
num_blocks = 100; #number of blocks to create


###### START SIMULATION
seed(seed_value);  #Set seed for randomness

#Initialize users (also, print their information)
enrolled_users = [ECDSA_user(w) for i in range(N)];
print_users(enrolled_users);
print_NetworkInfo(enrolled_users, N, w, X, max_num_tx, difficulty_coefficient);

#Public file with enrolled public keys
public_keys_file = [user.public_key for user in enrolled_users];

##Start blockchain creation
aux = "0x0000000000000000000000000000000000000000000000000000000000000000"; #hash of genesis block (first block in the chain)

#Timings
avg_times = zeros(max_num_tx); #j-th entry keeps record of number of attempts to clear a block with j transactions
count_blocks = zeros(max_num_tx); #j-th entry keeps record number of blocks with j transactions

avg_mining_time = 0; #variable to measure average mining time

#start blockchain
for block_number in range(1,num_blocks+1):

    print("Doing block # "+str(block_number));

    raw_transactions = create_raw_transactions(max_num_tx, enrolled_users); #create raw transactions for all users

    #Start clearing all the transactions in the block
    flag_mined = 0; #becomes 1 when all transactions have been mined
    seed_values = []; #seeds for PoFS
    user_identities = []; #identities of accepted users (i.e., senders of accepted transactions)
    
    #We keep track of required time and num of attempts
    start = timer(); 
    num_attempts = 0;

    #Start clearing all transactions in current block
    for i in range(len(raw_transactions)):

        m = raw_transactions[i][0]; #message to be signed in i-th transaction in the block
        signature = raw_transactions[i][1]; #fuzzy signature in i-th transaction in the block

        #Compute verifying public key
        verifying_pk = compute_pk(m,signature); #find public key that verifies the signature

        flag_cleared = 0; #flag_mined = 1 when clearing is over

        #Repeat clearing untile golden value is found
        while flag_cleared == 0:
            num_attempts += 1;
            flag_cleared, test_seed, delta_e, user_id = clearing(m,w,X,aux,verifying_pk,public_keys_file); #clearing attempt

        #User that prepared i-th transaction has been verified; proceed with next user (or produce the block, if all users have been verified)
        seed_values.append(test_seed);
        user_identities.append(user_id);
        print("- User #"+str(user_id)+", Delta e = "+str(delta_e));

    end1 = timer();#stop timer to measure clearing time


    #Create block: eventually, do classical PoW to compensate low number of transactions
    aux, json_block = create_block(aux, w, difficulty_coefficient, max_num_tx, block_number, raw_transactions, seed_values, user_identities);

    end2 = timer();#stop timer to measure block creation time

    avg_times[len(seed_values)-1] += (end2-start);
    count_blocks[len(seed_values)-1] += 1;

    avg_mining_time += ((end1 - start)/num_attempts);

    #If value is found, create the block and add it to the chain
    print("Block #"+str(block_number)+" has been created");
    print("Number of transactions: "+str(len(seed_values)));
    print("Block creation time: "+str( timedelta(seconds=end2-start)));
    print("Average mining time: "+str( timedelta(seconds=avg_mining_time)));
    print("--------------------------------");

    #Write block into json file
    block_name = 'Blocks/block'+str(block_number)+'.json'
    with open(block_name, "w") as write_file:
        json.dump(json_block, write_file, indent = 4)


#Print results
for i in range(max_num_tx):
    print("For blocks with "+str(i+1)+" transactions");
    print("Average creation time (in seconds) is "+str(timedelta(seconds = avg_times[i]/count_blocks[i])));
