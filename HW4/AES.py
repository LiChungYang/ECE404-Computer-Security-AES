import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 2), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_256(key_bv):
    byte_sub_table = encryp_gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 1, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal =
                                 byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8]
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def encryp_gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def decryp_gen_subbytes_table():
    de_subBytesTable = []
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        de_subBytesTable.append(int(b))
    return de_subBytesTable

def substitute(en_st_array, en_subBytesTable):
    for i in range(4):
        for j in range(4):
            tmp = en_st_array[j][i]
            #print(en_subBytesTable[tmp])
            en_st_array[j][i] = BitVector(intVal = en_subBytesTable[int(tmp)])
            en_st_array[j][i].pad_from_left(8-len(en_st_array[j][i]))
    return en_st_array
    
    
#shift rows for encrypt
def en_shiftrows(en_st_array):
    #en_st_array[1] = en_st_array[1][1:] + en_st_array[1][:1]
    #en_st_array[2] = en_st_array[2][2:] + en_st_array[2][:2]
    #en_st_array[3] = en_st_array[3][3:] + en_st_array[3][:3]
    for i in range(1, 4):
        en_st_array[i] = en_st_array[i][i:] + en_st_array[i][:i]
    return en_st_array
    
#shift rows for decrypt
def de_shiftrows(de_st_array):
    #print(type(de_st_array))
    for i in range(1, 4):
        de_st_array[i] = de_st_array[i][-i:] + de_st_array[i][:-i]
    return de_st_array
    
#mix column for encrypt
def en_mixcolumn(en_st_array):
    temparr = [[0 for x in range(4)] for x in range(4)]
    for j in range(4):
        temparr[0][j] =  en_st_array[0][j].gf_multiply_modular(BitVector(intVal = 2), AES_modulus, 8) ^ en_st_array[1][j].gf_multiply_modular(BitVector(intVal = 3), AES_modulus, 8) ^ en_st_array[2][j] ^ en_st_array[3][j]
        temparr[1][j] =  en_st_array[0][j] ^ en_st_array[1][j].gf_multiply_modular(BitVector(intVal = 2), AES_modulus, 8) ^ en_st_array[2][j].gf_multiply_modular(BitVector(intVal = 3), AES_modulus, 8) ^ en_st_array[3][j]
        temparr[2][j] =  en_st_array[0][j] ^ en_st_array[1][j] ^ en_st_array[2][j].gf_multiply_modular(BitVector(intVal = 2), AES_modulus, 8) ^ en_st_array[3][j].gf_multiply_modular(BitVector(intVal = 3), AES_modulus, 8)
        temparr[3][j] =  en_st_array[0][j].gf_multiply_modular(BitVector(intVal = 3), AES_modulus, 8) ^ en_st_array[1][j] ^ en_st_array[2][j] ^ en_st_array[3][j].gf_multiply_modular(BitVector(intVal = 2), AES_modulus, 8)
    return temparr
    
#mix column for decrypt  
def de_mixcolumn(de_st_array):
    temparr = [[0 for x in range(4)] for x in range(4)]
    for j in range(4):
        temparr[0][j] = de_st_array[0][j].gf_multiply_modular(BitVector(intVal = 0x0E), AES_modulus, 8) ^ de_st_array[1][j].gf_multiply_modular(BitVector(intVal = 0x0B), AES_modulus, 8) ^ de_st_array[2][j].gf_multiply_modular(BitVector(intVal = 0x0D), AES_modulus, 8) ^ de_st_array[3][j].gf_multiply_modular(BitVector(intVal = 9), AES_modulus, 8)
        temparr[1][j] = de_st_array[0][j].gf_multiply_modular(BitVector(intVal = 9), AES_modulus, 8) ^ de_st_array[1][j].gf_multiply_modular(BitVector(intVal = 0x0E), AES_modulus, 8) ^ de_st_array[2][j].gf_multiply_modular(BitVector(intVal = 0x0B), AES_modulus, 8) ^ de_st_array[3][j].gf_multiply_modular(BitVector(intVal = 0x0D), AES_modulus, 8)
        temparr[2][j] = de_st_array[0][j].gf_multiply_modular(BitVector(intVal = 0x0D), AES_modulus, 8) ^ de_st_array[1][j].gf_multiply_modular(BitVector(intVal = 9), AES_modulus, 8) ^ de_st_array[2][j].gf_multiply_modular(BitVector(intVal = 0x0E), AES_modulus, 8) ^ de_st_array[3][j].gf_multiply_modular(BitVector(intVal = 0x0B), AES_modulus, 8)
        temparr[3][j] = de_st_array[0][j].gf_multiply_modular(BitVector(intVal = 0x0B), AES_modulus, 8) ^ de_st_array[1][j].gf_multiply_modular(BitVector(intVal = 0x0D), AES_modulus, 8) ^ de_st_array[2][j].gf_multiply_modular(BitVector(intVal = 9), AES_modulus, 8) ^ de_st_array[3][j].gf_multiply_modular(BitVector(intVal = 0x0E), AES_modulus, 8)
    return temparr
        
## get_encryption_key.py
def get_encryption_key(keyfile):
    fope = open(keyfile, "r")
    text = fope.read()
    key = BitVector(textstring = text)
    return key

def arr_bitvec(st_array):
    templist = st_array[0][0]
    for i in range(4):
        for j in range(4):
            if i == 0  and j == 0:
                continue
            templist = templist + st_array[j][i]
                
    return templist


def arr_sti_bitlist(st_array):
    templist = (st_array[0][0]).get_hex_string_from_bitvector()
    for i in range(4):
        for j in range(4):
            if i == 0  and j == 0:
                continue
            templist = templist + (st_array[j][i]).get_hex_string_from_bitvector()
                
    return templist

def arr_text_bitlist(st_array):
    templist = (st_array[0][0]).get_text_from_bitvector()
    for i in range(4):
        for j in range(4):
            if i == 0  and j == 0:
                continue
            templist = templist + (st_array[j][i]).get_text_from_bitvector()
                
    return templist


def encrypt(message, keyfromfile):
    nonono = ""
    #find round key
    num_rounds = 14
    key_words = []
    key = get_encryption_key(keyfromfile)
    key_words = gen_key_schedule_256(key)

    key_schedule = []
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        key_schedule.append(keyword_in_ints)
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])

    #create state arrays (it's 4 x 4 because now we have 256 bits)
    statearray = [[0 for x in range(4)] for x in range(4)]
    statearr=BitVector(size=0)
    bv = BitVector (filename = message)
    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file( 128 )
        if bitvec._getsize() > 0:
            if bitvec._getsize() < 128:
                numadd = 128 - bitvec._getsize()
                bitvec.pad_from_right(numadd)
        for i in range(4):
            for j in range(4):
                statearray[j][i] = bitvec[32*i + 8*j:32*i + 8*(j+1)]
            
        copystatearr = statearray
        encrypttable = encryp_gen_subbytes_table()
            
        arrbit = arr_bitvec(copystatearr)
            
        #xor the first round key
        arrbit = arrbit ^ round_keys[0]
                
        for i in range(4):
            for j in range(4):
                copystatearr[j][i] = arrbit[32*i + 8*j:32*i + 8*(j+1)]
                
        for y in range(1,15):
        
            copystatearr = substitute(copystatearr, encrypttable)
            
            #copystatearr = arr_bitvec(copystatearr)
            #print(copystatearr.get_bitvector_in_hex())
            #sys.exit()
            
            #for p in range(4):
            #    for q in range(4):
            #        print(copystatearr[p][q].get_bitvector_in_hex(), end=' ')
            #    print("\n")
            
            copystatearr = en_shiftrows(copystatearr)
            
            #copystatearr = arr_bitvec(copystatearr)
            #print(copystatearr.get_bitvector_in_hex())
            #sys.exit()
            
            if y != 14:
                copystatearr = en_mixcolumn(copystatearr)
            
            #copystatearr = arr_bitvec(copystatearr)
            #print(copystatearr.get_bitvector_in_hex())
            #sys.exit()
            
            statearr = arr_bitvec(copystatearr)
            statearr = statearr ^ round_keys[y]
            for i in range(4):
                for j in range(4):
                    copystatearr[j][i] = statearr[32*i + 8*j:32*i + 8*(j+1)]
                    
            #for g in range(4):
            #    for t in range(4):
            #        file.write(copystatearr[g][t].get_bitvector_in_hex())
            
            
        nonono += arr_sti_bitlist(copystatearr)
        #print(copystatearr.get_bitvector_in_hex())
        #sys.exit()
            
    return(nonono)



def decrypt(message, keyfromfile):
    yesyes = ""
    #find round key
    num_rounds = 14
    key_words = []
    key = get_encryption_key(keyfromfile)
    key_words = gen_key_schedule_256(key)

    key_schedule = []
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        key_schedule.append(keyword_in_ints)
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])
    
    round_keys = round_keys[::-1]
    
    hex_file = open(message, "r")
    hex_string = hex_file.read()
    bv = BitVector (hexstring = hex_string)
    
    #create state arrays (it's 4 x 4 because now we have 256 bits)
    statearray = [[0 for x in range(4)] for x in range(4)]
    statearr=BitVector(size=0)
    #print("len", len(bv))
    
    for h in range(0, len(bv) // 128):
        #print("pp")
        bitvec = bv[h * 128:h * 128 + 128]
        if bitvec._getsize() > 0: 
            if bitvec._getsize() < 128:
                numadd = 128 - bitvec._getsize()
                bitvec.pad_from_right(numadd)
        for i in range(4):
            for j in range(4):
                statearray[j][i] = bitvec[32*i + 8*j:32*i + 8*(j+1)]
            
        copystatearr = statearray
        decrypttable = decryp_gen_subbytes_table()
            
        arrbit = arr_bitvec(copystatearr)
            
        #xor the first round key
        arrbit = arrbit ^ round_keys[0]
                
        for i in range(4):
            for j in range(4):
                copystatearr[j][i] = arrbit[32*i + 8*j:32*i + 8*(j+1)]
                
        for y in range(1,15):
            
            #for i in range(4):
            #    for j in range(4):
            #        copystatearr[j][i] = arrbit[32*i + 8*j:32*i + 8*(j+1)]
            
            copystatearr = de_shiftrows(copystatearr)
            #print("shiftrow", type(copystatearr))
            #copystatearr = arr_bitvec(copystatearr)
            #print("li")
            #print(copystatearr.get_bitvector_in_hex())
            #sys.exit()
        
            copystatearr = substitute(copystatearr, decrypttable)
            #print("sub", type(copystatearr))
            
            statearr = arr_bitvec(copystatearr)
            statearr = statearr ^ round_keys[y]
            for i in range(4):
                for j in range(4):
                    copystatearr[j][i] = statearr[32*i + 8*j:32*i + 8*(j+1)]
            #print(type(copystatearr))
            #print(type(statearr))
            
            if y != 14:
                copystatearr = de_mixcolumn(copystatearr)
                
            #print("mix", type(copystatearr))
            
            #copystatearr = arr_bitvec(copystatearr)
            #print(copystatearr.get_bitvector_in_hex())
            #sys.exit()
                    
            #for g in range(4):
            #    for t in range(4):
            #        file.write(copystatearr[g][t].get_bitvector_in_hex())
            
            
        yesyes += arr_text_bitlist(copystatearr)
        #print(copystatearr.get_bitvector_in_hex())
        #sys.exit()
            
    return(yesyes)

if __name__ == "__main__":
    if sys.argv[1] == '-e':
        #file = open(sys.argv[4], "w")
        out = encrypt(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == '-d':
        out = decrypt(sys.argv[2], sys.argv[3])
    file = open(sys.argv[4], "w")

    for item in out:
        file.write(item)
        #file.write(str(item))
