import json


#Print information about enrolled users

def print_users(enrolled_users):

    for i in range(len(enrolled_users)):

        this_user =  enrolled_users[i];
        print("User # "+str(i));
        
        print("Fixed sk : "+hex(this_user.fixed_sk));
        print("Noise when enrolling : "+str(this_user.enrolled_noise));
        print("Enrolled sk : "+hex(this_user.enrolled_sk));
        print("Enrolled pk : "+hex(this_user.public_key));
        print("----------------------------------------");

    return();

##################################################à

#Create a json file with Network Information (.e.g, users data)
def print_NetworkInfo(enrolled_users, N, w, X, max_num_tx, difficulty_coefficient):


    NetworkInfo = {'Num Users':N, 'w':w, 'MaxNumTx':max_num_tx, 'PoWCoefficient': difficulty_coefficient}; 
    with open("NetworkInfo.json", "w") as write_file:
        json.dump(NetworkInfo, write_file, indent = 4)

    #Add transactions
    for i in range(N):

        string_i = "User #"+str(i);
        data_i = {'Fixed sk':hex(enrolled_users[i].fixed_sk), 'Noise during enrolling':enrolled_users[i].enrolled_noise, 'sk during enrolling':hex(enrolled_users[i].enrolled_sk), 'Enrolled pk':hex(enrolled_users[i].public_key)};

        with open("NetworkInfo.json", "a") as write_file:
            json.dump([string_i, data_i], write_file, indent = 4)

    #Print file

    return();